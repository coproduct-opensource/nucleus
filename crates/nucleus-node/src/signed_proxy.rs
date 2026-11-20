use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response as AxumResponse};
use axum::routing::any;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use nucleus_client::drand::{DrandClient, DrandConfig, DrandFailMode};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

const HEADER_TIMESTAMP: &str = "x-nucleus-timestamp";
const HEADER_SIGNATURE: &str = "x-nucleus-signature";
const HEADER_ACTOR: &str = "x-nucleus-actor";
const HEADER_DRAND_ROUND: &str = "x-nucleus-drand-round";
const MAX_PROXY_BODY_BYTES: usize = 10 * 1024 * 1024;

/// The key this proxy signs `/v1/approve` with: the node's Ed25519 approval
/// key. Every pod verifies approvals against its PUBLIC half
/// (`nucleus.approval_pubkeys`, `NUCLEUS_TOOL_PROXY_APPROVAL_PUBKEYS`).
///
/// Until #2446 step 3 this was an enum with an `Hmac` arm for pods provisioned
/// an approval secret (the container driver's `tcp-hmac` transport), and every
/// other request was HMAC'd with the node's `proxy_auth_secret`. Both are
/// deleted: approvals are signed with this key, and nothing else is signed,
/// because every transport this proxy forwards over authenticates the node
/// itself (the vsock bridge, the peer-verified socket).
pub type ApprovalKey = Arc<ed25519_dalek::SigningKey>;

/// Where the pod's tool proxy is reached from the host.
///
/// `Tcp` is the loopback end of a Firecracker pod's vsock bridge, which reaches
/// a listener that admits only the host. `Unix` is the peer-verified socket of
/// a container or local pod (#2446): the proxy admits the node by
/// kernel-reported peer credentials (`nucleus-tool-proxy --listen-unix`).
/// Either way the transport is what authenticates the node, not anything this
/// proxy attaches.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyTarget {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl ProxyTarget {
    /// The authority the forwarded request names. A Unix socket has none, so
    /// the conventional `localhost` stands in (hyper needs SOME `Host`; the
    /// proxy on the other end does not route on it).
    fn authority(&self) -> String {
        match self {
            Self::Tcp(addr) => addr.to_string(),
            Self::Unix(_) => "localhost".to_string(),
        }
    }
}

impl From<SocketAddr> for ProxyTarget {
    fn from(addr: SocketAddr) -> Self {
        Self::Tcp(addr)
    }
}

impl std::fmt::Display for ProxyTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(addr) => write!(f, "{addr}"),
            Self::Unix(path) => write!(f, "unix://{}", path.display()),
        }
    }
}

#[derive(Clone)]
struct SignedProxyState {
    guest: Option<crate::guest_proof_provision::Signer>,
    proof: Option<Arc<nucleus_request_proof::LoopbackGate>>,
    target: ProxyTarget,
    approval: ApprovalKey,
    default_actor: Option<String>,
    /// Drand client for anchoring approval signatures.
    drand_client: Option<Arc<DrandClient>>,
}

pub struct SignedProxy {
    health: ProxyHealth,
    observation: ProxyObservation,
    listen_addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

/// Host-only proof material restricted by both the signer and receiving gate.
#[derive(Clone)]
pub(crate) struct ProxyObservation {
    addr: SocketAddr,
    key: Option<Arc<Vec<u8>>>,
}
impl ProxyObservation {
    pub(crate) fn proof(&self, address: &str, path: &str) -> std::io::Result<Option<String>> {
        if address != format!("http://{}", self.addr)
            || !nucleus_request_proof::is_supervisor_observation(path)
        {
            return Err(std::io::Error::other("observation target refused"));
        }
        use sha2::{Digest, Sha256};
        self.key
            .as_ref()
            .map(|key| {
                nucleus_identity::dpop::DpopProofBuilder::new("GET", &format!("{address}{path}"))
                    .with_access_token(&hex::encode(Sha256::digest(b"")))
                    .build(key)
                    .map_err(std::io::Error::other)
            })
            .transpose()
    }
}

fn observation_material(
    addr: SocketAddr,
) -> std::io::Result<(Arc<Vec<u8>>, nucleus_identity::did::JsonWebKey)> {
    use base64::Engine;
    let csr = nucleus_identity::CsrOptions::new("spiffe://node.local/ns/system/sa/observer")
        .generate()
        .map_err(std::io::Error::other)?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(csr.private_key().as_bytes())
        .map_err(|_| std::io::Error::other("observation key encoding"))?;
    let sample = nucleus_identity::dpop::DpopProofBuilder::new(
        "GET",
        &format!("http://{addr}/v1/workload/result"),
    )
    .build(&pem.contents)
    .map_err(std::io::Error::other)?;
    let header: nucleus_identity::dpop::DpopHeader = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(
                sample
                    .split('.')
                    .next()
                    .ok_or_else(|| std::io::Error::other("observation proof encoding"))?,
            )
            .map_err(std::io::Error::other)?,
    )
    .map_err(std::io::Error::other)?;
    Ok((Arc::new(pem.contents), header.jwk))
}

/// A host-owned probe capability; its private key can sign only the fixed
/// health request through this API. Never serialize or expose it to a caller.
#[derive(Clone)]
pub(crate) struct ProxyHealth {
    addr: SocketAddr,
    key: Option<Arc<Vec<u8>>>,
}
impl From<SocketAddr> for ProxyHealth {
    fn from(addr: SocketAddr) -> Self {
        Self { addr, key: None }
    }
}
impl ProxyHealth {
    pub(crate) fn addr(&self) -> SocketAddr {
        self.addr
    }
    pub(crate) fn request(&self) -> std::io::Result<String> {
        use sha2::{Digest, Sha256};
        let proof = match &self.key {
            Some(key) => {
                let token = hex::encode(Sha256::digest(b""));
                let proof = nucleus_identity::dpop::DpopProofBuilder::new(
                    "GET",
                    &format!("http://{}/v1/health", self.addr),
                )
                .with_access_token(&token)
                .build(key)
                .map_err(std::io::Error::other)?;
                format!("DPoP: {proof}\r\n")
            }
            None => String::new(),
        };
        Ok(format!(
            "GET /v1/health HTTP/1.1\r\nHost: {}\r\n{proof}Connection: close\r\n\r\n",
            self.addr
        ))
    }
}

/// Trusted launch configuration, never derived from forwarded HTTP headers.
pub struct ProxyProofConfig {
    pub(crate) guest: Option<crate::guest_proof_provision::Signer>,
    pub key: nucleus_identity::did::JsonWebKey,
    pub replay_path: PathBuf,
    pub expires: u64,
}

impl std::fmt::Debug for SignedProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignedProxy")
            .field("listen_addr", &self.listen_addr)
            .finish()
    }
}

impl SignedProxy {
    /// Start the signed proxy without drand anchoring.
    ///
    /// This method maintains backward compatibility. For drand-anchored approval
    /// signatures, use [`start_with_drand`] instead.
    #[allow(dead_code)]
    pub async fn start(
        target: impl Into<ProxyTarget>,
        approval: ApprovalKey,
        default_actor: Option<String>,
    ) -> std::io::Result<Self> {
        Self::start_with_drand(target, approval, default_actor, None).await
    }

    /// Start the signed proxy with optional drand anchoring for approval requests.
    ///
    /// When `drand_config` is provided and enabled, approval requests (`/v1/approve`)
    /// will include a drand round number in the signature. This prevents pre-computation
    /// of an approval signature.
    ///
    /// # Drand Anchoring
    ///
    /// With drand anchoring:
    /// - Message format: `"{round}.{timestamp}.{actor}.{body}"`
    /// - Adds header: `x-nucleus-drand-round: <round>`
    ///
    /// Without drand anchoring:
    /// - Message format: `"{timestamp}.{actor}.{body}"`
    ///
    /// Any other request is forwarded with no signature at all.
    pub async fn start_with_drand(
        target: impl Into<ProxyTarget>,
        approval: ApprovalKey,
        default_actor: Option<String>,
        drand_config: Option<DrandConfig>,
    ) -> std::io::Result<Self> {
        Self::start_with_proof(target, approval, default_actor, drand_config, None).await
    }

    pub async fn start_with_proof(
        target: impl Into<ProxyTarget>,
        approval: ApprovalKey,
        default_actor: Option<String>,
        drand_config: Option<DrandConfig>,
        proof: Option<ProxyProofConfig>,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let listen_addr = listener.local_addr()?;
        let mut health = ProxyHealth::from(listen_addr);
        let mut observation = ProxyObservation {
            addr: listen_addr,
            key: None,
        };
        let guest = proof.as_ref().and_then(|config| config.guest.clone());
        let proof = proof
            .map(|config| {
                use base64::Engine;
                let csr =
                    nucleus_identity::CsrOptions::new("spiffe://node.local/ns/system/sa/health")
                        .generate()
                        .map_err(std::io::Error::other)?;
                let (_, pem) = x509_parser::pem::parse_x509_pem(csr.private_key().as_bytes())
                    .map_err(|_| std::io::Error::other("health key encoding"))?;
                let sample = nucleus_identity::dpop::DpopProofBuilder::new(
                    "GET",
                    &format!("http://{listen_addr}/v1/health"),
                )
                .build(&pem.contents)
                .map_err(std::io::Error::other)?;
                let header: nucleus_identity::dpop::DpopHeader = serde_json::from_slice(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD
                        .decode(
                            sample
                                .split('.')
                                .next()
                                .ok_or_else(|| std::io::Error::other("health proof encoding"))?,
                        )
                        .map_err(std::io::Error::other)?,
                )
                .map_err(std::io::Error::other)?;
                health.key = Some(Arc::new(pem.contents));
                let (secret, public) = observation_material(listen_addr)?;
                observation.key = Some(secret);
                nucleus_request_proof::LoopbackGate::open(
                    &format!("http://{listen_addr}"),
                    &config.replay_path,
                    config.key,
                    config.expires,
                )
                .and_then(|gate| gate.with_health_key(header.jwk))
                .and_then(|gate| gate.with_observation_key(public))
                .map(Arc::new)
                .map_err(std::io::Error::other)
            })
            .transpose()?;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let drand_client = drand_config.filter(|c| c.enabled).and_then(|c| {
            // The NODE is the host process, not a sandboxed pod: pod
            // egress policy does not apply to it. Stated at the call
            // site rather than assumed.
            let admitted = nucleus_client::egress::EgressPolicy::unrestricted_host_process()
                .admit("api.drand.sh")
                .expect("an unrestricted policy admits every host");
            match DrandClient::new(c, admitted) {
                Ok(client) => Some(Arc::new(client)),
                Err(why) => {
                    // The node is not PID 1, so it degrades rather than exiting.
                    // Escalation still refuses without drand — see the `else`
                    // arm in the tool-proxy's escalation handler — so this is a
                    // loud degradation, not a silent bypass.
                    tracing::error!("drand disabled for signed proxy: {why}");
                    None
                }
            }
        });

        let state = SignedProxyState {
            guest,
            proof,
            target: target.into(),
            approval,
            default_actor,
            drand_client,
        };

        let app = Router::new().fallback(any(proxy_handler)).with_state(state);

        let task = tokio::spawn(async move {
            let server = axum::serve(listener, app).with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            });

            if let Err(err) = server.await {
                error!("signed proxy server error: {err}");
            }
        });

        Ok(Self {
            health,
            observation,
            listen_addr,
            shutdown: Some(shutdown_tx),
            task,
        })
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub(crate) fn health_endpoint(&self) -> ProxyHealth {
        self.health.clone()
    }

    pub(crate) fn observation_endpoint(&self) -> ProxyObservation {
        self.observation.clone()
    }

    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        // Graceful shutdown waits for in-flight requests, and `forward_request`
        // has no timeout of its own; this carries no identity, so it is bounded.
        crate::teardown_bound::join(
            "signed proxy",
            &mut self.task,
            std::time::Duration::from_secs(5),
        )
        .await;
    }
}

async fn proxy_handler(
    State(state): State<SignedProxyState>,
    request: axum::http::Request<Body>,
) -> Result<AxumResponse, AxumResponse> {
    let (parts, body) = request.into_parts();
    let body_bytes = to_bytes(body, MAX_PROXY_BODY_BYTES)
        .await
        .map_err(|e| proxy_error(StatusCode::BAD_REQUEST, format!("body error: {e}")))?;

    if let Some(gate) = &state.proof {
        if parts.uri.query().is_some() || parts.headers.contains_key(HEADER_ACTOR) {
            return Err(proxy_error(
                StatusCode::UNAUTHORIZED,
                "unbound request context refused".into(),
            ));
        }
        let proof = crate::request_proof::one(&parts.headers, "dpop")
            .ok()
            .flatten()
            .ok_or_else(|| {
                proxy_error(StatusCode::UNAUTHORIZED, "request proof required".into())
            })?;
        let verified = gate
            .verify_request(proof, parts.method.as_str(), parts.uri.path(), &body_bytes)
            .map_err(|_| proxy_error(StatusCode::UNAUTHORIZED, "request proof refused".into()))?;
        let _key = verified
            .into_thumbprint(nucleus_request_proof::unix_now())
            .map_err(|_| proxy_error(StatusCode::UNAUTHORIZED, "request proof expired".into()))?;
    }

    let actor = extract_actor(&parts.headers, state.default_actor.as_deref());
    let timestamp = now_unix();
    let path = parts.uri.path();

    let is_approval = path == "/v1/approve";

    // Sign an approval with the node's Ed25519 approval key, which every pod
    // verifies against the public half (see `build_message` for the bytes).
    let sign_approval = |round: Option<u64>| -> String {
        use ed25519_dalek::Signer as _;
        let message = build_message(round, timestamp, actor.as_deref(), &body_bytes);
        hex::encode(state.approval.sign(&message).to_bytes())
    };

    // For approval requests, try to anchor with drand. Nothing else is signed.
    let (signature, drand_round) = if is_approval {
        if let Some(ref drand_client) = state.drand_client {
            match drand_client.current_round().await {
                Ok(round) => (sign_approval(Some(round)), Some(round)),
                Err(e) => {
                    // Handle based on fail mode
                    // Note: The DrandClient handles Cached mode internally by using
                    // recently cached rounds (up to 60s old). If we get an error here,
                    // it means even the cache is unavailable or too stale.
                    match drand_client.config().fail_mode {
                        DrandFailMode::Strict => {
                            return Err(proxy_error(
                                StatusCode::SERVICE_UNAVAILABLE,
                                format!("drand unavailable: {e}"),
                            ));
                        }
                        DrandFailMode::Cached => {
                            // Cached mode fallback: the DrandClient already tried to use
                            // its cache, so if we're here, the cache is too old.
                            // We fall back to non-drand signing as a last resort.
                            warn!(
                                "drand unavailable and cache expired, falling back to non-anchored signing: {e}"
                            );
                            (sign_approval(None), None)
                        }
                    }
                }
            }
        } else {
            // No drand client configured, use standard signing
            (sign_approval(None), None)
        }
    } else {
        // The transport authenticates the node (#2446 step 3): the shared
        // secret that used to sign these is deleted.
        (String::new(), None)
    };

    let uri = build_target_uri(&state.target, parts.uri.path_and_query())
        .map_err(|e| proxy_error(StatusCode::BAD_REQUEST, format!("bad uri: {e}")))?;

    let mut headers = filter_headers(&parts.headers);
    // Never forward the client's proof as the host's identity. The guest sees
    // a fresh proof for this pod's configured logical origin and exact body.
    if let Some(guest) = &state.guest {
        if parts.uri.query().is_some() {
            return Err(proxy_error(
                StatusCode::BAD_REQUEST,
                "unbound guest query".into(),
            ));
        }
        let proof = guest
            .proof(parts.method.as_str(), parts.uri.path(), &body_bytes)
            .map_err(|_| proxy_error(StatusCode::UNAUTHORIZED, "guest proof refused".into()))?;
        headers.insert(
            "dpop",
            HeaderValue::from_str(&proof).map_err(|_| {
                proxy_error(StatusCode::UNAUTHORIZED, "guest proof encoding".into())
            })?,
        );
    }
    headers.insert(
        axum::http::header::HOST,
        HeaderValue::from_str(&state.target.authority())
            .map_err(|e| proxy_error(StatusCode::BAD_REQUEST, format!("bad host: {e}")))?,
    );
    headers.insert(
        axum::http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&body_bytes.len().to_string())
            .map_err(|e| proxy_error(StatusCode::BAD_REQUEST, format!("bad length: {e}")))?,
    );
    if is_approval {
        headers.insert(
            HEADER_TIMESTAMP,
            HeaderValue::from_str(&timestamp.to_string())
                .map_err(|e| proxy_error(StatusCode::BAD_REQUEST, format!("bad timestamp: {e}")))?,
        );
        headers.insert(
            HEADER_SIGNATURE,
            HeaderValue::from_str(&signature)
                .map_err(|e| proxy_error(StatusCode::BAD_REQUEST, format!("bad signature: {e}")))?,
        );
    }
    if let Some(actor_value) = actor.as_ref() {
        headers.insert(
            HEADER_ACTOR,
            HeaderValue::from_str(actor_value)
                .map_err(|e| proxy_error(StatusCode::BAD_REQUEST, format!("bad actor: {e}")))?,
        );
    }
    if let Some(round) = drand_round {
        headers.insert(
            HEADER_DRAND_ROUND,
            HeaderValue::from_str(&round.to_string()).map_err(|e| {
                proxy_error(StatusCode::BAD_REQUEST, format!("bad drand round: {e}"))
            })?,
        );
    }

    let mut outbound = Request::builder()
        .method(parts.method)
        .uri(uri)
        .version(parts.version)
        .body(Full::new(body_bytes))
        .map_err(|e| proxy_error(StatusCode::BAD_REQUEST, format!("bad request: {e}")))?;
    *outbound.headers_mut() = headers;

    let response = forward_request(&state.target, outbound)
        .await
        .map_err(|e| proxy_error(StatusCode::BAD_GATEWAY, format!("proxy error: {e}")))?;

    Ok(response)
}

fn filter_headers(headers: &HeaderMap) -> HeaderMap {
    let mut filtered = HeaderMap::new();
    for (name, value) in headers.iter() {
        if name == axum::http::header::HOST
            || name.as_str().eq_ignore_ascii_case(HEADER_TIMESTAMP)
            || name.as_str().eq_ignore_ascii_case(HEADER_SIGNATURE)
            || name.as_str().eq_ignore_ascii_case(HEADER_ACTOR)
            || name.as_str().eq_ignore_ascii_case(HEADER_DRAND_ROUND)
        {
            continue;
        }
        filtered.append(name, value.clone());
    }
    filtered
}

fn extract_actor(headers: &HeaderMap, default_actor: Option<&str>) -> Option<String> {
    if let Some(actor) = default_actor {
        let trimmed = actor.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    headers
        .get(HEADER_ACTOR)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
        .filter(|value| !value.is_empty())
}

fn build_target_uri(
    target: &ProxyTarget,
    path_and_query: Option<&axum::http::uri::PathAndQuery>,
) -> Result<Uri, axum::http::Error> {
    let mut builder = Uri::builder().scheme("http");
    builder = builder.authority(target.authority());
    if let Some(path) = path_and_query {
        builder = builder.path_and_query(path.as_str());
    } else {
        builder = builder.path_and_query("/");
    }
    builder.build()
}

/// The bytes both primitives sign: `"{round}.{timestamp}.{actor}.{body}"`
/// when drand-anchored (the round cannot be predicted, which is what stops
/// pre-computation), `"{timestamp}.{actor}.{body}"` otherwise.
fn build_message(round: Option<u64>, timestamp: i64, actor: Option<&str>, body: &[u8]) -> Vec<u8> {
    let actor_value = actor.unwrap_or("");
    let ts = timestamp.to_string();
    let mut message = Vec::with_capacity(ts.len() + actor_value.len() + 24 + body.len());
    if let Some(round) = round {
        message.extend_from_slice(round.to_string().as_bytes());
        message.push(b'.');
    }
    message.extend_from_slice(ts.as_bytes());
    message.push(b'.');
    message.extend_from_slice(actor_value.as_bytes());
    message.push(b'.');
    message.extend_from_slice(body);
    message
}

async fn forward_request(
    target: &ProxyTarget,
    request: Request<Full<axum::body::Bytes>>,
) -> Result<AxumResponse, Box<dyn std::error::Error + Send + Sync>> {
    match target {
        ProxyTarget::Tcp(addr) => send_over(TcpStream::connect(addr).await?, request).await,
        ProxyTarget::Unix(path) => send_over(UnixStream::connect(path).await?, request).await,
    }
}

/// One HTTP/1 exchange over an already-connected stream, whatever it is
/// (TCP to a vsock bridge, Unix socket to a peer-verified proxy).
async fn send_over<S>(
    stream: S,
    request: Request<Full<axum::body::Bytes>>,
) -> Result<AxumResponse, Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await?;

    tokio::spawn(async move {
        if let Err(err) = connection.await {
            error!("signed proxy connection error: {err}");
        }
    });

    let response: hyper::Response<Incoming> = sender.send_request(request).await?;
    let (mut parts, body) = response.into_parts();
    let collected = body.collect().await?;
    let bytes = collected.to_bytes();

    // Collection decodes the upstream's transfer framing. The new exact-size
    // body gets its own framing from Axum; retaining `chunked` alongside its
    // generated Content-Length makes Hyper reject the response outright.
    // Trailers were consumed with that stream and are not forwarded here.
    parts.headers.remove(axum::http::header::TRANSFER_ENCODING);
    parts.headers.remove(axum::http::header::TRAILER);

    Ok(axum::http::Response::from_parts(parts, Body::from(bytes)))
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn proxy_error(status: StatusCode, message: String) -> AxumResponse {
    info!("signed proxy error: {message}");
    (status, message).into_response()
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn dpop_refusals_never_reach_the_downstream_proxy() {
        use base64::Engine;
        use nucleus_identity::dpop::{DpopHeader, DpopProofBuilder};
        use sha2::{Digest, Sha256};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let key = nucleus_identity::CsrOptions::new("spiffe://test/ns/client/sa/tool")
            .generate()
            .unwrap();
        let (_, pem) = x509_parser::pem::parse_x509_pem(key.private_key().as_bytes()).unwrap();
        let sample = DpopProofBuilder::new("POST", "http://127.0.0.1:1234/v1/read")
            .build(&pem.contents)
            .unwrap();
        let header: DpopHeader = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(sample.split('.').next().unwrap())
                .unwrap(),
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut spec: crate::PodSpec = serde_json::from_value(serde_json::json!({
            "apiVersion":"nucleus/v1","kind":"Pod","metadata":{},"spec":{"policy":{"type":"profile","name":"default"}}
        }))
        .unwrap();
        spec.metadata.labels.insert(
            crate::tool_proof_provision::LABEL.into(),
            serde_json::json!({"expires":now_unix()+300}).to_string(),
        );
        let id = uuid::Uuid::new_v4();
        crate::guest_proof_provision::provision(&mut spec, &dir.path().join("keys"), id).unwrap();
        let guest = crate::guest_proof_provision::Signer::load(&spec, &dir.path().join("keys"), id)
            .unwrap();
        let config: serde_json::Value =
            serde_json::from_str(&spec.metadata.labels[crate::guest_proof_provision::LABEL])
                .unwrap();
        let guest_public: nucleus_identity::did::JsonWebKey =
            serde_json::from_value(config["key"].clone()).unwrap();
        let gate = Arc::new(
            nucleus_request_proof::ProofGate::open(
                config["origin"].as_str().unwrap(),
                &dir.path().join("guest-replay"),
            )
            .unwrap(),
        );
        let received = Arc::new(AtomicUsize::new(0));
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let count = received.clone();
        let target_app = Router::new().fallback(any(move |request: axum::extract::Request| {
            let gate = gate.clone();
            let public = guest_public.clone();
            let count = count.clone();
            async move {
                let (parts, body) = request.into_parts();
                let body = to_bytes(body, 1024).await.unwrap();
                let digest = hex::encode(Sha256::digest(&body));
                let proof = parts.headers.get("dpop").unwrap().to_str().unwrap();
                gate.verify(
                    proof,
                    parts.method.as_str(),
                    parts.uri.path(),
                    Some(&digest),
                    &public,
                )
                .unwrap()
                .into_thumbprint(nucleus_request_proof::unix_now())
                .unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                "forwarded"
            }
        }));
        let task = tokio::spawn(async move { axum::serve(target, target_app).await.unwrap() });
        let proxy = SignedProxy::start_with_proof(
            target_addr,
            test_key(),
            Some("fixture".into()),
            None,
            Some(ProxyProofConfig {
                guest,
                key: header.jwk,
                replay_path: dir.path().join("proofs"),
                expires: u64::try_from(now_unix()).unwrap_or(0) + 300,
            }),
        )
        .await
        .unwrap();
        let url = format!("http://{}/v1/read", proxy.listen_addr());
        let body = "{\"path\":\"fixture\"}";
        let proof = DpopProofBuilder::new("POST", &url)
            .with_access_token(&hex::encode(Sha256::digest(body.as_bytes())))
            .build(&pem.contents)
            .unwrap();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        for request in [
            client.post(&url).body(body),
            client.post(&url).header("dpop", &proof).body("changed"),
            client
                .post(&url)
                .header("dpop", &proof)
                .header("dpop", &proof)
                .body(body),
            client.get(&url).header("dpop", &proof).body(body),
            client
                .post(format!("{url}?unbound=true"))
                .header("dpop", &proof)
                .body(body),
            client
                .post(&url)
                .header("dpop", &proof)
                .header(HEADER_ACTOR, "other")
                .body(body),
        ] {
            assert_eq!(
                request.send().await.unwrap().status(),
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(received.load(Ordering::SeqCst), 0);
        assert_eq!(
            client
                .post(&url)
                .header("dpop", &proof)
                .body(body)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            client
                .post(&url)
                .header("dpop", &proof)
                .body(body)
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(received.load(Ordering::SeqCst), 1);
        let health = proxy.health_endpoint();
        assert_eq!(
            client
                .get(format!("http://{}/v1/health", health.addr()))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut stream = TcpStream::connect(health.addr()).await.unwrap();
            stream
                .write_all(health.request().unwrap().as_bytes())
                .await
                .unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                stream.read_to_end(&mut response),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(response.starts_with(b"HTTP/1.1 200 "));
        }
        assert_eq!(received.load(Ordering::SeqCst), 2);
        let observer = proxy.observation_endpoint();
        let origin = format!("http://{}", proxy.listen_addr());
        assert!(
            observer
                .proof("http://127.0.0.1:1", "/v1/workload/result")
                .is_err()
        );
        for forbidden in ["/v1/health", "/v1/read", "/v1/workload/result?extra=1"] {
            assert!(observer.proof(&origin, forbidden).is_err());
        }
        for path in [
            "/v1/workload/result",
            "/v1/workload/logs/stdout",
            "/v1/workload/logs/stderr",
        ] {
            let url = format!("{origin}{path}");
            assert_eq!(
                client.get(&url).send().await.unwrap().status(),
                StatusCode::UNAUTHORIZED
            );
            let observation = observer.proof(&origin, path).unwrap().unwrap();
            assert_eq!(
                client
                    .post(&url)
                    .header("dpop", &observation)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                client
                    .get(&url)
                    .header("dpop", &observation)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
            assert_eq!(
                client
                    .get(&url)
                    .header("dpop", &observation)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(received.load(Ordering::SeqCst), 5);
        proxy.shutdown().await;
        task.abort();
    }

    #[tokio::test]
    async fn a_chunked_request_is_reframed_before_forwarding() {
        use axum::routing::post;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let backend = Router::new().route("/echo", post(|body: String| async move { body }));
        let server = tokio::spawn(async move { axum::serve(listener, backend).await.unwrap() });
        let proxy = SignedProxy::start(address, test_key(), None).await.unwrap();
        let mut stream = TcpStream::connect(proxy.listen_addr()).await.unwrap();
        stream.write_all(b"POST /echo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n").await.unwrap();
        let mut reply = Vec::new();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_to_end(&mut reply),
        )
        .await;
        proxy.shutdown().await;
        server.abort();
        result.unwrap().unwrap();
        assert!(
            reply.starts_with(b"HTTP/1.1 200 "),
            "{}",
            String::from_utf8_lossy(&reply)
        );
        assert!(
            reply.ends_with(b"onetwo"),
            "{}",
            String::from_utf8_lossy(&reply)
        );
    }
    #[tokio::test]
    async fn a_chunked_guest_response_survives_the_buffering_proxy() {
        use axum::routing::get;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let backend = Router::new().route(
            "/reply",
            get(|| async {
                Body::from_stream(tokio_stream::iter([
                    Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"one")),
                    Ok(axum::body::Bytes::from_static(b"two")),
                ]))
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, backend).await.unwrap() });
        let proxy = SignedProxy::start(address, test_key(), None).await.unwrap();
        let request = Request::builder()
            .uri(format!("http://{}/reply", proxy.listen_addr()))
            .header(axum::http::header::HOST, proxy.listen_addr().to_string())
            .body(Full::new(axum::body::Bytes::new()))
            .unwrap();
        let response = send_over(
            TcpStream::connect(proxy.listen_addr()).await.unwrap(),
            request,
        )
        .await;
        proxy.shutdown().await;
        server.abort();
        let bytes = to_bytes(response.unwrap().into_body(), 1024).await.unwrap();
        assert_eq!(&bytes[..], b"onetwo");
    }
    use super::*;

    /// **The framing contract with the guest-side verifier, pinned as bytes.**
    /// The tool-proxy's `auth` module reconstructs exactly
    /// `"{round}.{timestamp}.{actor}.{body}"` (or without the round) from the
    /// request headers and verifies the signature over it. The two live in
    /// different crates, so nothing but this test notices if one side's
    /// framing drifts — and a drift fails EVERY approval, far from the cause.
    #[test]
    fn the_signed_message_framing_matches_the_verifier() {
        assert_eq!(
            build_message(Some(42), 1000, Some("op"), b"BODY"),
            b"42.1000.op.BODY".to_vec()
        );
        // No round, no actor: the separators stay (an empty actor is framed
        // as an empty segment, not an absent one).
        assert_eq!(build_message(None, 1000, None, b"B"), b"1000..B".to_vec());
    }

    /// The signed proxy forwards over a Unix socket exactly as over TCP: the
    /// request reaches the socket's server and the reply comes back through.
    /// Pinned against a real bound socket so a regression in
    /// `forward_request`'s Unix arm cannot hide behind the TCP path that every
    /// other test exercises.
    ///
    /// #2446 step 3: an ordinary request carries NO signature and no
    /// timestamp. The shared secret that signed it is deleted; the socket
    /// authenticates the node. Red before: both headers were attached.
    #[tokio::test]
    async fn a_unix_target_is_reached_with_no_shared_secret_signature() {
        use axum::routing::get;
        use std::sync::Mutex;

        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("proxy.sock");
        let seen: Arc<Mutex<Option<HeaderMap>>> = Arc::new(Mutex::new(None));
        let seen_in = Arc::clone(&seen);
        let backend = Router::new().route(
            "/v1/ping",
            get(move |headers: HeaderMap| {
                let seen_in = Arc::clone(&seen_in);
                async move {
                    *seen_in.lock().unwrap() = Some(headers);
                    "ok"
                }
            }),
        );
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, backend).await;
        });

        let proxy = SignedProxy::start(
            ProxyTarget::Unix(sock.clone()),
            test_key(),
            Some("node".to_string()),
        )
        .await
        .unwrap();

        // Client side over plain TCP to the proxy, using the same one-exchange
        // helper the proxy uses (no reqwest: the workspace's reqwest has no
        // crypto provider installed in tests, and none is needed here).
        let request = Request::builder()
            .method("GET")
            .uri(format!("http://{}/v1/ping", proxy.listen_addr()))
            .header(axum::http::header::HOST, proxy.listen_addr().to_string())
            .body(Full::new(axum::body::Bytes::new()))
            .unwrap();
        let stream = TcpStream::connect(proxy.listen_addr()).await.unwrap();
        let response = send_over(stream, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1 << 16).await.unwrap();
        assert_eq!(&body[..], b"ok");

        let headers = seen
            .lock()
            .unwrap()
            .clone()
            .expect("backend saw the request");
        assert!(
            !headers.contains_key(HEADER_SIGNATURE),
            "no shared-secret signature: {headers:?}"
        );
        assert!(!headers.contains_key(HEADER_TIMESTAMP), "{headers:?}");
        assert_eq!(headers.get(HEADER_ACTOR).unwrap(), "node");
        assert_eq!(headers.get(axum::http::header::HOST).unwrap(), "localhost");

        proxy.shutdown().await;
        server.abort();
    }

    fn test_key() -> ApprovalKey {
        Arc::new(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]))
    }

    /// An approval is the one request still signed, with the node's Ed25519
    /// key, and the signature verifies under the public half over the bytes
    /// the guest rebuilds from the forwarded headers.
    #[tokio::test]
    async fn an_approval_is_signed_with_the_ed25519_key() {
        use axum::routing::post;
        use std::sync::Mutex;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let seen: Arc<Mutex<Option<HeaderMap>>> = Arc::new(Mutex::new(None));
        let seen_in = Arc::clone(&seen);
        let backend = Router::new().route(
            "/v1/approve",
            post(move |headers: HeaderMap| {
                let seen_in = Arc::clone(&seen_in);
                async move {
                    *seen_in.lock().unwrap() = Some(headers);
                    "ok"
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, backend).await.unwrap() });
        let key = test_key();
        let proxy = SignedProxy::start(address, Arc::clone(&key), Some("node".to_string()))
            .await
            .unwrap();
        let request = Request::builder()
            .method("POST")
            .uri(format!("http://{}/v1/approve", proxy.listen_addr()))
            .header(axum::http::header::HOST, proxy.listen_addr().to_string())
            .body(Full::new(axum::body::Bytes::from_static(b"{}")))
            .unwrap();
        let stream = TcpStream::connect(proxy.listen_addr()).await.unwrap();
        let response = send_over(stream, request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        proxy.shutdown().await;
        server.abort();

        let headers = seen.lock().unwrap().clone().expect("backend saw it");
        let timestamp: i64 = headers
            .get(HEADER_TIMESTAMP)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .expect("an approval carries its timestamp");
        let sig: [u8; 64] = hex::decode(headers.get(HEADER_SIGNATURE).unwrap().to_str().unwrap())
            .unwrap()
            .try_into()
            .expect("an Ed25519 signature is 64 bytes");
        let message = build_message(None, timestamp, Some("node"), b"{}");
        assert!(
            key.verifying_key()
                .verify_strict(&message, &ed25519_dalek::Signature::from_bytes(&sig))
                .is_ok()
        );
    }

    /// An Ed25519 approval signature produced the way the handler produces it
    /// verifies under `verify_strict` with the public half — the check the
    /// guest performs against `nucleus.approval_pubkeys`.
    #[test]
    fn an_approval_signature_round_trips_to_the_public_key() {
        use ed25519_dalek::Signer as _;
        let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let message = build_message(Some(9), 1234, Some("approver"), b"{}");
        let sig_hex = hex::encode(key.sign(&message).to_bytes());
        let sig_bytes: [u8; 64] = hex::decode(&sig_hex).unwrap().try_into().unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        assert!(
            key.verifying_key()
                .verify_strict(&message, &signature)
                .is_ok()
        );
    }
}
