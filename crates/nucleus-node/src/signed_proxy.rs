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
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{error, info};

use crate::auth::sign_message;

const HEADER_TIMESTAMP: &str = "x-nucleus-timestamp";
const HEADER_SIGNATURE: &str = "x-nucleus-signature";
const HEADER_ACTOR: &str = "x-nucleus-actor";
const MAX_PROXY_BODY_BYTES: usize = 10 * 1024 * 1024;

#[derive(Clone)]
struct SignedProxyState {
    target: SocketAddr,
    secret: Arc<Vec<u8>>,
    default_actor: Option<String>,
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
    pub async fn start(
        target: SocketAddr,
        secret: Arc<Vec<u8>>,
        default_actor: Option<String>,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let listen_addr = listener.local_addr()?;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let state = SignedProxyState {
            target,
            secret,
            default_actor,
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
    let signature = sign_request(&state.secret, timestamp, actor.as_deref(), &body_bytes);

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
