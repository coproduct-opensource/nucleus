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

/// How this proxy signs `/v1/approve` requests.
///
/// One enum rather than two `Option`s: a proxy holding both an approval
/// secret and an approval key would have two ways to sign the same request,
/// and which one the guest accepts is a property of how the POD was
/// provisioned — the launch path that started this proxy knows, so it picks.
#[derive(Clone)]
pub enum ApprovalSigning {
    /// Shared-secret HMAC — pods provisioned with `approval_secret` (the
    /// env-delivered container paths).
    Hmac(Arc<Vec<u8>>),
    /// Ed25519 with the node's approval signing key — Firecracker pods, which
    /// verify against the PUBLIC half (`nucleus.approval_pubkeys`) and hold
    /// no approval secret at all.
    Ed25519(Arc<ed25519_dalek::SigningKey>),
}

#[derive(Clone)]
struct SignedProxyState {
    target: SocketAddr,
    secret: Arc<Vec<u8>>,
    approval: Option<ApprovalSigning>,
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
        approval: Option<ApprovalSigning>,
        default_actor: Option<String>,
    ) -> std::io::Result<Self> {
        Self::start_with_drand(target, secret, approval, default_actor, None).await
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
        approval: Option<ApprovalSigning>,
        default_actor: Option<String>,
        drand_config: Option<DrandConfig>,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let listen_addr = listener.local_addr()?;
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let drand_client =
            drand_config
                .filter(|c| c.enabled)
                .and_then(|c| match DrandClient::new(c) {
                    Ok(client) => Some(Arc::new(client)),
                    Err(why) => {
                        // The node is not PID 1, so it degrades rather than exiting.
                        // Escalation still refuses without drand — see the `else`
                        // arm in the tool-proxy's escalation handler — so this is a
                        // loud degradation, not a silent bypass.
                        tracing::error!("drand disabled for signed proxy: {why}");
                        None
                    }
                });

        let state = SignedProxyState {
            target,
            secret,
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

    let is_approval = path == "/v1/approve";

    // Sign an approval with the approval AUTHORITY — Ed25519 when the pod
    // verifies against public keys, HMAC when it was provisioned a secret,
    // the plain auth secret when no approval authority was configured. The
    // message bytes are identical across primitives (see `build_message`), so
    // the guest-side verifier changed only its primitive, not its framing.
    let sign_approval = |round: Option<u64>| -> String {
        let message = build_message(round, timestamp, actor.as_deref(), &body_bytes);
        match state.approval {
            Some(ApprovalSigning::Ed25519(ref key)) => {
                use ed25519_dalek::Signer as _;
                hex::encode(key.sign(&message).to_bytes())
            }
            Some(ApprovalSigning::Hmac(ref secret)) => sign_message(secret, &message),
            None => sign_message(&state.secret, &message),
        }
    };

    // For approval requests, try to anchor with drand
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
                            warn!("drand unavailable and cache expired, falling back to non-anchored signing: {e}");
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
        // Non-approval requests use standard signing with the plain auth secret.
        (
            sign_request(&state.secret, timestamp, actor.as_deref(), &body_bytes),
            None,
        )
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

fn sign_request(secret: &[u8], timestamp: i64, actor: Option<&str>, body: &[u8]) -> String {
    sign_message(secret, &build_message(None, timestamp, actor, body))
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

#[cfg(test)]
mod tests {
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
        assert!(key
            .verifying_key()
            .verify_strict(&message, &signature)
            .is_ok());
    }
}
