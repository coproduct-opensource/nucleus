//! HTTP client for the nucleus tool-proxy.
//!
//! [`ProxyClient`] mirrors the Python SDK's `ProxyClient`, providing typed methods
//! for all tool-proxy endpoints (`/v1/read`, `/v1/write`, `/v1/run`, etc.).
//!
//! All operations go through the tool-proxy which enforces the permission lattice
//! at the pod boundary.
//!
//! # Two transports
//!
//! The URL decides, through `nucleus_client::endpoint::ProxyEndpoint` (the one
//! parser every client shares):
//!
//! * `http(s)://host:port` — a TCP listener, which anyone who can route to it
//!   can connect to, so requests carry an [`AuthStrategy`] or mTLS.
//! * `unix:///path/to/socket` — the workload door the runtime names in the
//!   workload's `NUCLEUS_TOOL_PROXY_URL` (#3122). The proxy reads the caller's
//!   uid from the kernel, so a request carries no secret, and a client handed
//!   one is refused at construction: a workload that holds a proxy credential
//!   was given it by mistake (#2446).

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::AuthStrategy;
use crate::auth::MtlsConfig;
use crate::error::{Error, from_error_payload};
use nucleus_client::endpoint::ProxyEndpoint;
use nucleus_client::wire::{RunRequest, RunResponse};

/// Requests over a Unix socket are addressed to this placeholder: the
/// connector dials the socket, never this host, and the proxy does not route
/// on `Host`. The same placeholder `nucleus-mcp`'s door transport uses.
const UNIX_BASE_URL: &str = "http://localhost";

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

/// The proxy's reply, read through the shared wire type. This used to pick
/// `exit_code` out of a `Value`; the proxy sends `status`, so every caller saw
/// -1 whatever the command did (2026-09-29).
impl From<RunResponse> for RunOutput {
    fn from(r: RunResponse) -> Self {
        Self {
            exit_code: r.status,
            stdout: r.stdout,
            stderr: r.stderr,
        }
    }
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
    /// Create a new proxy client for `base_url`: `http(s)://host:port`, or
    /// `unix:///path/to/socket` for the workload door.
    ///
    /// # Errors
    ///
    /// [`Error::Config`] when the URL names neither transport, or names a Unix
    /// socket and `auth` or `mtls` is also given: the socket authenticates the
    /// caller by its uid, and a credential sent over it would be one the
    /// caller should not hold.
    pub fn new(
        base_url: &str,
        auth: Option<Box<dyn AuthStrategy>>,
        mtls: Option<&MtlsConfig>,
    ) -> Result<Self, Error> {
        // Ensure ring crypto provider is installed for rustls (idempotent)
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none());
        let endpoint = ProxyEndpoint::parse(base_url).map_err(|e| Error::Config(e.to_string()))?;
        let base_url = match endpoint {
            ProxyEndpoint::Unix { socket } => {
                if auth.is_some() || mtls.is_some() {
                    return Err(Error::Config(format!(
                        "the tool-proxy at `{base_url}` is a Unix socket, which authenticates the \
                         caller by its uid; this client was also given a credential (an \
                         AuthStrategy or mTLS), which nothing reaching the proxy this way should \
                         hold. Pass neither."
                    )));
                }
                builder = unix_socket(builder, socket)?;
                UNIX_BASE_URL.to_string()
            }
            ProxyEndpoint::Http { base } => {
                validate_tcp_endpoint(&base, mtls.is_some())?;
                builder = if base.starts_with("https://") {
                    builder.https_only(true)
                } else {
                    builder.no_proxy()
                };
                if let Some(mtls) = mtls {
                    let identity = mtls.reqwest_identity()?;
                    builder = builder.identity(identity);

                    if let Some(ca) = mtls.reqwest_ca_cert()? {
                        builder = builder.tls_certs_merge([ca]);
                    }
                }
                base
            }
        };

        let client = builder
            .build()
            .map_err(|e| Error::Config(format!("failed to build HTTP client: {}", e)))?;

        Ok(Self {
            base_url,
            client,
            auth: auth.map(Arc::from),
        })
    }

    /// Build with custom connection settings while retaining transport policy.
    /// A prebuilt client cannot be accepted: its redirect policy is opaque.
    pub fn with_client_builder(
        base_url: &str,
        builder: reqwest::ClientBuilder,
        auth: Option<Arc<dyn AuthStrategy>>,
    ) -> Result<Self, Error> {
        // Custom TLS configuration is opaque, so this constructor requires HTTPS.
        validate_tcp_endpoint(base_url, true)?;
        let client = builder
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::Config(e.to_string()))?;
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            auth,
        })
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

        if response.status().is_redirection() {
            return Err(Error::Other(format!(
                "proxy redirect refused (HTTP {status})"
            )));
        }
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
        let mut req = RunRequest::new(args.iter().map(|a| (*a).to_string()).collect());
        req.stdin = stdin.map(str::to_string);
        req.directory = directory.map(str::to_string);
        let payload = serde_json::to_value(&req)?;
        let data = self.request("POST", "/v1/run", Some(&payload)).await?;
        Ok(RunOutput::from(serde_json::from_value::<RunResponse>(
            data,
        )?))
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

/// Point every connection `builder` makes at `socket`.
#[cfg(unix)]
fn unix_socket(
    builder: reqwest::ClientBuilder,
    socket: std::path::PathBuf,
) -> Result<reqwest::ClientBuilder, Error> {
    Ok(builder.unix_socket(socket))
}

/// A Unix-socket proxy is unreachable from a host without Unix sockets.
#[cfg(not(unix))]
fn unix_socket(
    _builder: reqwest::ClientBuilder,
    socket: std::path::PathBuf,
) -> Result<reqwest::ClientBuilder, Error> {
    Err(Error::Config(format!(
        "the tool-proxy socket {} needs a Unix host",
        socket.display()
    )))
}

/// TCP plaintext is reserved for literal loopback without mTLS. Hostnames
/// cannot qualify by resolving to loopback once and elsewhere later.
fn validate_tcp_endpoint(base: &str, mtls: bool) -> Result<(), Error> {
    let url = reqwest::Url::parse(base).map_err(|e| Error::Config(e.to_string()))?;
    let loopback = url
        .host_str()
        .and_then(|h| h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback && !mtls) {
        return Err(Error::Config("use HTTPS for remote TCP or mTLS; plaintext is only allowed on a literal loopback address without mTLS".into()));
    }
    if url.host_str().is_none() || !url.username().is_empty() || url.password().is_some() {
        return Err(Error::Config(
            "proxy URL must have a host and no embedded credentials".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn redirects_never_receive_signed_requests() {
        use std::io::{Read, Write};
        let origin = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let destination = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let url = format!("http://{}", origin.local_addr().unwrap());
        let location = format!("http://{}/stolen", destination.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut socket, _) = origin.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut request = [0u8; 8192];
            assert!(socket.read(&mut request).unwrap() > 0);
            write!(socket, "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        });
        let auth = crate::auth::HmacAuth::new(b"test-only-key", Some("operator"));
        let client = ProxyClient::new(&url, Some(Box::new(auth)), None).unwrap();
        assert!(client.list_pods().await.is_err());
        server.join().unwrap();
        assert_eq!(
            destination.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn transport_refuses_remote_plaintext_and_mtls_downgrades() {
        for url in [
            "http://example.com",
            "http://localhost",
            "http://127.0.0.1.example.com",
            "ftp://127.0.0.1",
        ] {
            assert!(ProxyClient::new(url, None, None).is_err(), "{url}");
        }
        let mtls = MtlsConfig::new("/missing/cert", "/missing/key");
        assert!(
            ProxyClient::new("http://127.0.0.1", None, Some(&mtls))
                .err()
                .unwrap()
                .to_string()
                .contains("HTTPS")
        );
        assert!(ProxyClient::new("https://example.com", None, None).is_ok());
        assert!(ProxyClient::new("http://[::1]", None, None).is_ok());
        assert!(
            ProxyClient::with_client_builder("http://127.0.0.1", reqwest::Client::builder(), None)
                .is_err()
        );
    }

    #[test]
    fn test_proxy_client_trims_trailing_slash() {
        let client = ProxyClient::new("http://127.0.0.1:8080/", None, None).unwrap();
        assert_eq!(client.base_url, "http://127.0.0.1:8080");
    }

    #[test]
    fn test_proxy_client_no_slash() {
        let client = ProxyClient::new("http://127.0.0.1:8080", None, None).unwrap();
        assert_eq!(client.base_url, "http://127.0.0.1:8080");
    }

    /// One request as a stand-in door received it, read off a real Unix socket.
    #[cfg(unix)]
    struct Seen {
        head: String,
        body: Vec<u8>,
    }

    /// Serve one request on `listener` with `reply`, reporting what arrived.
    #[cfg(unix)]
    fn door_once(
        listener: std::os::unix::net::UnixListener,
        reply: String,
    ) -> std::thread::JoinHandle<Seen> {
        use std::io::{Read, Write};
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            let head_end = loop {
                let n = stream.read(&mut buf).expect("read request");
                assert!(n > 0, "connection closed mid-request");
                req.extend_from_slice(&buf[..n]);
                if let Some(i) = req.windows(4).position(|w| w == b"\r\n\r\n") {
                    break i + 4;
                }
            };
            let head = String::from_utf8_lossy(&req[..head_end]).to_ascii_lowercase();
            let len: usize = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:").map(str::to_owned))
                .map_or(0, |v| v.trim().parse().expect("content-length"));
            while req.len() < head_end + len {
                let n = stream.read(&mut buf).expect("read body");
                assert!(n > 0, "connection closed mid-body");
                req.extend_from_slice(&buf[..n]);
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                reply.len()
            );
            stream.write_all(response.as_bytes()).expect("write");
            Seen {
                head,
                body: req[head_end..].to_vec(),
            }
        })
    }

    /// #2446 step 1: a workload reaches its proxy through the door URL the
    /// runtime gives it, over the socket, holding no credential. Red before:
    /// the client handed `unix://` to reqwest as a URL, which refused the
    /// scheme, so an SDK caller inside a pod could not reach its proxy at all.
    /// The reply is built from the SERVER's wire type (ADR 0007 G).
    #[cfg(unix)]
    #[tokio::test]
    async fn a_client_on_the_door_reaches_its_proxy_with_no_credential() {
        use nucleus_client::wire::{ReadRequest, ReadResponse};
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("workload.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind");
        let reply = serde_json::to_string(&ReadResponse {
            contents: "hello from the door".into(),
        })
        .unwrap();
        let door = door_once(listener, reply);

        let url = ProxyEndpoint::unix(&socket).to_string();
        let client = ProxyClient::new(&url, None, None).expect("a door client");
        let contents = client.read("hello.txt").await.expect("read over the door");
        assert_eq!(contents, "hello from the door");

        let seen = door.join().expect("door thread");
        assert!(seen.head.starts_with("post /v1/read "), "{}", seen.head);
        assert!(
            !seen.head.contains("x-nucleus-signature"),
            "a door request carries no HMAC: {}",
            seen.head
        );
        let req: ReadRequest = serde_json::from_slice(&seen.body).expect("a wire ReadRequest");
        assert_eq!(req.path, "hello.txt");
    }

    /// A credential handed to a door client is refused at construction, not
    /// carried silently. Red before: `new` accepted any URL with any auth.
    #[test]
    fn a_door_client_refuses_a_credential() {
        let auth = crate::auth::HmacAuth::new(b"test-token-123", Some("agent"));
        let err = ProxyClient::new(
            "unix:///run/nucleus-door/workload.sock",
            Some(Box::new(auth)),
            None,
        )
        .err()
        .expect("a door client holding an HMAC key is refused");
        assert!(err.to_string().contains("Unix socket"), "{err}");

        let mtls = MtlsConfig::new("/nonexistent/cert.pem", "/nonexistent/key.pem");
        assert!(
            ProxyClient::new("unix:///run/nucleus-door/workload.sock", None, Some(&mtls)).is_err()
        );
    }

    /// A URL naming neither transport is refused by the shared parser rather
    /// than handed to the HTTP stack to fail on first use.
    #[test]
    fn a_url_naming_no_transport_is_refused() {
        for bad in ["localhost:8080", "unix://run/x.sock", "vsock://3:4000", ""] {
            assert!(ProxyClient::new(bad, None, None).is_err(), "{bad:?}");
        }
    }

    /// Built from what the PROXY serializes, not from a hand-written mock. The
    /// old test mocked `"exit_code": 0` -- the SDK's assumption rather than the
    /// server's shape -- and so passed while every real call read -1.
    #[test]
    fn a_run_reply_from_the_proxy_keeps_its_exit_status() {
        let reply = serde_json::to_value(RunResponse {
            status: 3,
            success: false,
            stdout: "hello\n".into(),
            stderr: String::new(),
        })
        .unwrap();
        let output = RunOutput::from(serde_json::from_value::<RunResponse>(reply).unwrap());
        assert_eq!(output.exit_code, 3);
        assert_eq!(output.stdout, "hello\n");
    }
}
