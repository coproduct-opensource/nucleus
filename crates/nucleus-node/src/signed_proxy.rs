use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response as AxumResponse};
use axum::routing::any;
use axum::Router;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::Request;
use hyper_util::rt::TokioIo;
use nucleus_client::drand::{DrandClient, DrandConfig, DrandFailMode};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::auth::sign_message;

const HEADER_TIMESTAMP: &str = "x-nucleus-timestamp";
const HEADER_SIGNATURE: &str = "x-nucleus-signature";
const HEADER_ACTOR: &str = "x-nucleus-actor";
const HEADER_DRAND_ROUND: &str = "x-nucleus-drand-round";
const MAX_PROXY_BODY_BYTES: usize = 10 * 1024 * 1024;

#[derive(Clone)]
struct SignedProxyState {
    target: SocketAddr,
    secret: Arc<Vec<u8>>,
    approval_secret: Option<Arc<Vec<u8>>>,
    default_actor: Option<String>,
    /// Drand client for anchoring approval signatures.
    drand_client: Option<Arc<DrandClient>>,
}

pub struct SignedProxy {
    listen_addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
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
        target: SocketAddr,
        secret: Arc<Vec<u8>>,
        approval_secret: Option<Arc<Vec<u8>>>,
        default_actor: Option<String>,
    ) -> std::io::Result<Self> {
        Self::start_with_drand(target, secret, approval_secret, default_actor, None).await
    }

    /// Start the signed proxy with optional drand anchoring for approval requests.
    ///
    /// When `drand_config` is provided and enabled, approval requests (`/v1/approve`)
    /// will include a drand round number in the signature. This prevents pre-computation
    /// attacks even if the HMAC secret is compromised.
    ///
    /// # Drand Anchoring
    ///
    /// With drand anchoring:
    /// - Message format: `"{round}.{timestamp}.{actor}.{body}"`
    /// - Adds header: `x-nucleus-drand-round: <round>`
    ///
    /// Without drand anchoring (or for non-approval requests):
    /// - Message format: `"{timestamp}.{actor}.{body}"`
    pub async fn start_with_drand(
        target: SocketAddr,
        secret: Arc<Vec<u8>>,
        approval_secret: Option<Arc<Vec<u8>>>,
        default_actor: Option<String>,
        drand_config: Option<DrandConfig>,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let listen_addr = listener.local_addr()?;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let drand_client = drand_config
            .filter(|c| c.enabled)
            .map(|c| Arc::new(DrandClient::new(c)));

        let state = SignedProxyState {
            target,
            secret,
            approval_secret,
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
            listen_addr,
            shutdown: Some(shutdown_tx),
            task,
        })
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = self.task.await;
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

    let actor = extract_actor(&parts.headers, state.default_actor.as_deref());
    let timestamp = now_unix();
    let path = parts.uri.path();

    // Determine secret and whether to use drand anchoring
    let is_approval = path == "/v1/approve";
    let secret = if is_approval {
        state.approval_secret.as_ref().unwrap_or(&state.secret)
    } else {
        &state.secret
    };

    // For approval requests, try to anchor with drand
    let (signature, drand_round) = if is_approval {
        if let Some(ref drand_client) = state.drand_client {
            match drand_client.current_round().await {
                Ok(round) => {
                    let sig =
                        sign_request_with_drand(secret, round, timestamp, actor.as_deref(), &body_bytes);
                    (sig, Some(round))
                }
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
                            warn!("drand unavailable and cache expired, falling back to non-anchored signing: {e}");
                            (sign_request(secret, timestamp, actor.as_deref(), &body_bytes), None)
                        }
                    }
                }
            }
        } else {
            // No drand client configured, use standard signing
            (sign_request(secret, timestamp, actor.as_deref(), &body_bytes), None)
        }
    } else {
        // Non-approval requests use standard signing
        (sign_request(secret, timestamp, actor.as_deref(), &body_bytes), None)
    };

    let uri = build_target_uri(state.target, parts.uri.path_and_query())
        .map_err(|e| proxy_error(StatusCode::BAD_REQUEST, format!("bad uri: {e}")))?;

    let mut headers = filter_headers(&parts.headers);
    headers.insert(
        axum::http::header::HOST,
        HeaderValue::from_str(&state.target.to_string())
            .map_err(|e| proxy_error(StatusCode::BAD_REQUEST, format!("bad host: {e}")))?,
    );
    headers.insert(
        axum::http::header::CONTENT_LENGTH,
        HeaderValue::from_str(&body_bytes.len().to_string())
            .map_err(|e| proxy_error(StatusCode::BAD_REQUEST, format!("bad length: {e}")))?,
    );
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
            HeaderValue::from_str(&round.to_string())
                .map_err(|e| proxy_error(StatusCode::BAD_REQUEST, format!("bad drand round: {e}")))?,
        );
    }

    let mut outbound = Request::builder()
        .method(parts.method)
        .uri(uri)
        .version(parts.version)
        .body(Full::new(body_bytes))
        .map_err(|e| proxy_error(StatusCode::BAD_REQUEST, format!("bad request: {e}")))?;
    *outbound.headers_mut() = headers;

    let response = forward_request(state.target, outbound)
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
    target: SocketAddr,
    path_and_query: Option<&axum::http::uri::PathAndQuery>,
) -> Result<Uri, axum::http::Error> {
    let mut builder = Uri::builder().scheme("http");
    builder = builder.authority(target.to_string());
    if let Some(path) = path_and_query {
        builder = builder.path_and_query(path.as_str());
    } else {
        builder = builder.path_and_query("/");
    }
    builder.build()
}

fn sign_request(secret: &[u8], timestamp: i64, actor: Option<&str>, body: &[u8]) -> String {
    let actor_value = actor.unwrap_or("");
    let ts = timestamp.to_string();
    let mut message = Vec::with_capacity(ts.len() + actor_value.len() + 2 + body.len());
    message.extend_from_slice(ts.as_bytes());
    message.push(b'.');
    message.extend_from_slice(actor_value.as_bytes());
    message.push(b'.');
    message.extend_from_slice(body);
    sign_message(secret, &message)
}

/// Sign a request with drand anchoring.
///
/// Message format: `"{round}.{timestamp}.{actor}.{body}"`
///
/// This prevents pre-computation attacks because the drand round cannot be
/// predicted in advance.
fn sign_request_with_drand(
    secret: &[u8],
    drand_round: u64,
    timestamp: i64,
    actor: Option<&str>,
    body: &[u8],
) -> String {
    let actor_value = actor.unwrap_or("");
    let round_str = drand_round.to_string();
    let ts = timestamp.to_string();
    let mut message =
        Vec::with_capacity(round_str.len() + ts.len() + actor_value.len() + 3 + body.len());
    message.extend_from_slice(round_str.as_bytes());
    message.push(b'.');
    message.extend_from_slice(ts.as_bytes());
    message.push(b'.');
    message.extend_from_slice(actor_value.as_bytes());
    message.push(b'.');
    message.extend_from_slice(body);
    sign_message(secret, &message)
}

async fn forward_request(
    target: SocketAddr,
    request: Request<Full<axum::body::Bytes>>,
) -> Result<AxumResponse, Box<dyn std::error::Error + Send + Sync>> {
    let stream = TcpStream::connect(target).await?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await?;

    tokio::spawn(async move {
        if let Err(err) = connection.await {
            error!("signed proxy connection error: {err}");
        }
    });

    let response: hyper::Response<Incoming> = sender.send_request(request).await?;
    let (parts, body) = response.into_parts();
    let collected = body.collect().await?;
    let bytes = collected.to_bytes();

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
