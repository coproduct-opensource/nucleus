//! The anonymous, read-only evidence listener (#2706; ADR 0011, "As built").
//!
//! # Why a separate listener
//!
//! A receipt names the SHA-256 of the node evidence in force when it was
//! signed. The stranger who checks that receipt has no node credential, and
//! the node's API listener asks for a client certificate before any route
//! runs, so `GET /v1/node/evidence/{digest}` there is unreachable to exactly
//! the party it exists for (`docs/findings/attested-node-live-run.md`,
//! finding 3). This listener — opt-in, `--public-evidence-addr` — asks for no
//! client certificate and serves two routes, nothing else:
//!
//! * `GET /v1/evidence/{sha256}` — a stored evidence document, by the digest a
//!   receipt names. Content-addressed: the name is 64 lowercase hex digits,
//!   checked before anything touches the disk, and the bytes are re-hashed
//!   before they are sent, so a corrupted store answers 500 rather than serving
//!   a document under a name it does not have.
//! * `GET /v1/node/keys` — the executor's Ed25519 public key (the key receipts
//!   are signed with, and the key every quote binds) and whether this node has
//!   evidence at all.
//!
//! The router is built by [`router`] alone, and a test enumerates every route
//! the node's API mounts and requires each to be absent here. Mounting the full
//! API on this listener turns that test red (ADR 0007 A-19).
//!
//! # What is not served, and why
//!
//! * **Challenge quotes.** `POST /v1/node/evidence/challenge` costs a TPM quote
//!   per request. It stays on the mTLS listener; a stranger checks a receipt
//!   against the EPOCH evidence the receipt names, which needs no quote.
//! * **The latest epoch, or any listing.** The receipt names the digest; a
//!   stranger never has to discover one. Serving "latest" would make this
//!   listener a liveness oracle for the node's attester and nothing more.
//! * **Anything about pods.** No pod id, log, result or receipt.
//!
//! # Nothing here is a trust root
//!
//! The evidence document is self-verifying: its bytes hash to the name the
//! signed receipt carries, and its quote is checked against the relying
//! party's own AK pin or certificate roots. The keys document is a
//! convenience: the key a stranger should believe is the one the evidence's
//! qualifying data binds, which `nucleus_node_evidence::appraise` checks.
//!
//! # Why TLS and not plaintext
//!
//! Integrity of what matters does not depend on the transport, so plaintext
//! would not weaken a verdict. It is still refused: one transport stance for
//! every listener the node opens, and an operator who wants strangers to reach
//! this over ordinary HTTPS gives it a certificate for a DNS name
//! (`--public-evidence-tls-cert/-key`); without one, the node's own SVID is
//! presented, as on the federation listener.
//!
//! # Bounds
//!
//! Handshakes are bounded and timed out (`tls_ingress`). Requests carry no body
//! ([`MAX_BODY_BYTES`]). At most [`MAX_IN_FLIGHT`] are served at once, beyond
//! which the answer is 503 immediately; a token bucket refills at
//! `--public-evidence-requests-per-sec`, beyond which the answer is 429. A
//! stored document larger than [`MAX_DOCUMENT_BYTES`] is not served, and a read
//! that takes longer than [`READ_TIMEOUT`] is abandoned.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path as UrlPath, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::node_evidence::is_digest;

/// A GET carries no body; this is only what a misbehaving client can make the
/// node buffer.
const MAX_BODY_BYTES: usize = 1024;
/// Requests served at once.
const MAX_IN_FLIGHT: usize = 32;
/// The largest stored document served. A narrow IMA log keeps a document under
/// 100 KiB (the live run's were 88 KB); a document past this is a node
/// misconfiguration, and serving it anonymously would be a bandwidth lever.
pub(crate) const MAX_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;
/// A read from the store that has not finished in this long is abandoned.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Operator flags for the public evidence listener.
#[derive(clap::Args, Debug, Clone)]
pub(crate) struct PublicEvidenceArgs {
    /// Address for the anonymous, read-only evidence listener: server-
    /// authenticated TLS, NO client certificate, serving only
    /// `GET /v1/evidence/{sha256}` and `GET /v1/node/keys`. Unset, nothing is
    /// served; evidence is then reachable only over the mTLS API.
    #[arg(
        long = "public-evidence-addr",
        env = "NUCLEUS_NODE_PUBLIC_EVIDENCE_ADDR"
    )]
    pub(crate) addr: Option<String>,
    /// PEM certificate chain this listener presents instead of the node's own
    /// SVID, for a DNS name an ordinary HTTPS client can match. With
    /// `--public-evidence-tls-key`, or neither.
    #[arg(
        long = "public-evidence-tls-cert",
        env = "NUCLEUS_NODE_PUBLIC_EVIDENCE_TLS_CERT"
    )]
    pub(crate) tls_cert: Option<PathBuf>,
    /// PEM private key for `--public-evidence-tls-cert`.
    #[arg(
        long = "public-evidence-tls-key",
        env = "NUCLEUS_NODE_PUBLIC_EVIDENCE_TLS_KEY"
    )]
    pub(crate) tls_key: Option<PathBuf>,
    /// Requests per second across all callers (token bucket; the burst is one
    /// second's worth). Zero is refused at start.
    #[arg(
        long = "public-evidence-requests-per-sec",
        env = "NUCLEUS_NODE_PUBLIC_EVIDENCE_REQUESTS_PER_SEC",
        default_value_t = 20
    )]
    pub(crate) requests_per_sec: u32,
}

impl Default for PublicEvidenceArgs {
    /// Off: no address.
    fn default() -> Self {
        Self {
            addr: None,
            tls_cert: None,
            tls_key: None,
            requests_per_sec: 20,
        }
    }
}

/// Where documents come from: the attester's store, or the reason there is
/// none. Two cases, matched exhaustively — never an empty directory standing in
/// for "no attester" (ADR 0007 A-2).
#[derive(Clone, Debug)]
pub(crate) enum Store {
    Dir(PathBuf),
    Unattested(String),
}

impl From<Result<PathBuf, String>> for Store {
    fn from(r: Result<PathBuf, String>) -> Self {
        match r {
            Ok(dir) => Self::Dir(dir),
            Err(reason) => Self::Unattested(reason),
        }
    }
}

/// A token bucket shared by every caller. Global, not per address: a map keyed
/// by caller is itself unbounded state an anonymous caller can grow.
struct Bucket {
    tokens: f64,
    last: Instant,
    rate: f64,
}

impl Bucket {
    fn take(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.rate);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Clone)]
pub(crate) struct PublicState {
    store: Store,
    keys: Bytes,
    in_flight: Arc<Semaphore>,
    bucket: Arc<Mutex<Bucket>>,
}

impl PublicState {
    /// `requests_per_sec` must be positive; [`spawn`] refuses zero first.
    pub(crate) fn new(store: Store, executor_key: [u8; 32], requests_per_sec: u32) -> Self {
        let platform = match &store {
            Store::Dir(_) => serde_json::json!({ "evidence": "tpm" }),
            Store::Unattested(reason) => serde_json::json!({ "unattested": reason }),
        };
        let keys = serde_json::json!({
            "profile": "nucleus-node-keys/v1",
            "executor": { "alg": "ed25519", "public_key_hex": hex::encode(executor_key) },
            "node_platform": platform,
        });
        let rate = f64::from(requests_per_sec.max(1));
        Self {
            store,
            keys: Bytes::from(keys.to_string()),
            in_flight: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            bucket: Arc::new(Mutex::new(Bucket {
                tokens: rate,
                last: Instant::now(),
                rate,
            })),
        }
    }
}

async fn limit(State(st): State<PublicState>, req: Request, next: Next) -> Response {
    let Ok(_permit) = st.in_flight.clone().try_acquire_owned() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "busy").into_response();
    };
    let allowed = match st.bucket.lock() {
        Ok(mut b) => b.take(Instant::now()),
        // A poisoned limiter refuses rather than waves everything through
        // (ADR 0007 B-4: no default on an operand that decides a gate).
        Err(_) => false,
    };
    if !allowed {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    next.run(req).await
}

/// `GET /v1/evidence/{sha256}`.
async fn by_digest(State(st): State<PublicState>, UrlPath(digest): UrlPath<String>) -> Response {
    if !is_digest(&digest) {
        return (StatusCode::BAD_REQUEST, "expected 64 lowercase hex digits").into_response();
    }
    let dir = match &st.store {
        Store::Unattested(reason) => {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({ "unattested": reason })),
            )
                .into_response();
        }
        Store::Dir(dir) => dir,
    };
    let path = dir.join(format!("{digest}.json"));
    let read = async {
        let meta = tokio::fs::metadata(&path).await?;
        if meta.len() > MAX_DOCUMENT_BYTES {
            return Ok(None);
        }
        tokio::fs::read(&path).await.map(Some)
    };
    let bytes = match tokio::time::timeout(READ_TIMEOUT, read).await {
        Ok(Ok(Some(b))) if b.len() as u64 <= MAX_DOCUMENT_BYTES => b,
        Ok(Ok(_)) => {
            warn!(%digest, "stored evidence exceeds the public listener's size cap; not served");
            return (StatusCode::INTERNAL_SERVER_ERROR, "document too large").into_response();
        }
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            return StatusCode::NOT_FOUND.into_response();
        }
        Ok(Err(e)) => {
            warn!(%digest, error = %e, "reading stored evidence failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    if hex::encode(nucleus_node_evidence::evidence_digest(&bytes)) != digest {
        warn!(%digest, "stored evidence does not hash to its name; not served");
        return (StatusCode::INTERNAL_SERVER_ERROR, "store corrupt").into_response();
    }
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            // Content-addressed: the bytes under this name never change.
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        bytes,
    )
        .into_response()
}

/// `GET /v1/node/keys`.
async fn keys(State(st): State<PublicState>) -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        st.keys.clone(),
    )
        .into_response()
}

/// The public listener's router: exactly two routes, a body cap and the limits.
/// The ONE constructor; nothing else builds this listener's routes.
pub(crate) fn router(st: PublicState) -> Router {
    use axum::routing::get;
    Router::new()
        .route("/v1/evidence/{digest}", get(by_digest))
        .route("/v1/node/keys", get(keys))
        .layer(axum::middleware::from_fn_with_state(st.clone(), limit))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(st)
}

/// Serve the public evidence listener, if `--public-evidence-addr` is set.
/// Returns once bound; serving continues on a task.
///
/// # Errors
/// A zero request rate (a listener that can only refuse), one TLS file without
/// the other, an unloadable certificate, or an address that does not bind.
pub(crate) async fn spawn(
    state: &crate::NodeState,
    args: &PublicEvidenceArgs,
) -> Result<(), crate::ApiError> {
    let Some(listen) = args.addr.as_deref() else {
        return Ok(());
    };
    let err = crate::ApiError::Driver;
    if args.requests_per_sec == 0 {
        return Err(err(
            "--public-evidence-requests-per-sec must be positive".into()
        ));
    }
    let config = crate::tls_ingress::server_config(
        state,
        args.tls_cert.as_deref(),
        args.tls_key.as_deref(),
        "--public-evidence-tls",
    )
    .await
    .map_err(err)?;
    let tcp = tokio::net::TcpListener::bind(listen).await?;
    let addr = tcp.local_addr()?;
    let app = router(PublicState::new(
        state.node_platform.evidence_store().into(),
        state
            .trust_gate
            .executor_signing_key
            .verifying_key()
            .to_bytes(),
        args.requests_per_sec,
    ));
    crate::tls_ingress::serve_tls(tcp, config, app, "public-evidence");
    info!(%addr, "public evidence listening (server-authenticated TLS, no client certificate, read-only)");
    Ok(())
}

#[cfg(test)]
#[path = "public_evidence_tests.rs"]
mod tests;
