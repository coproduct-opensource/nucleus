// Served only from the broker listener, which the Firecracker launch path
// starts (`cfg(target_os = "linux")`). Same pattern as `broker_transport`.
#![cfg_attr(all(not(test), not(target_os = "linux")), allow(dead_code))]

//! The host performs a STREAMED call, so a model call fits through the same
//! door a small one does (#2696 P4, #2906, #3031).
//!
//! # What this adds to `broker_perform`
//!
//! [`crate::broker_perform`] serves a request to act whose body travels inside
//! one signed frame, which the host must buffer whole before it can verify it.
//! The frame is bounded at 256 KiB for that reason, and the reply is bounded
//! the same way. A model API breaks both: a prompt with a long context is
//! larger, and the reply arrives over minutes as server-sent events. Raising
//! the bound would make the host buffer whatever the guest sends.
//!
//! Here only the OPEN frame is signed and buffered (8 KiB, a query's bound).
//! The body follows on the same connection as bounded chunks
//! ([`nucleus_cred_protocol::stream`]), each one charged to the pod's egress
//! balance BEFORE the host forwards it, and the reply comes back the same way.
//! The host never holds more than one chunk of either direction.
//!
//! # The decision is the perform path's, not a copy of it
//!
//! Decide, resolve the name, fix the path: [`crate::broker_perform::resolve`].
//! Mint and fetch the credential: [`crate::broker_perform::credential_header`].
//! Both are the functions `handle_perform` calls, so a streamed call can never
//! be permitted where the same perform would be refused (ADR 0007 G).
//!
//! # The balance is the pod's ONE balance
//!
//! [`StreamContext::egress`] is the same `Arc<EgressMeter>` the perform path
//! and every other egress path of this pod hold (#2905). The open frame's
//! guest-chosen bytes (path and media type) are charged first, then each chunk
//! as it arrives. A chunk the ledger refuses is never forwarded: the upstream
//! request is aborted, and the guest is told why by name, because the counts
//! are its own traffic and the remedy (a larger declared ceiling) is the
//! operator's to apply.
//!
//! # What this does not do
//!
//! It does not mediate. The kernel decision, the flow graph and the effect
//! gate ran in the guest's proxy before it signed the open frame, exactly as
//! for a perform; see `broker_perform`'s module docs for why the host's own
//! decision is a second gate rather than a replacement. Download bytes are not
//! charged (the ledger counts upload only, see `portcullis::egress_budget`);
//! they are bounded per call by [`StreamLimits`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nucleus_cred_broker::PodIdentity;
use nucleus_cred_protocol::stream::io::{Chunk, read_chunk, write_chunks, write_end, write_line};
use nucleus_cred_protocol::{StreamEnd, StreamHead, StreamRequest};
use portcullis::PermissionLattice;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::broker_perform::{Asked, CredentialMiss, InjectedHeader};
use crate::federated_credential::PodCredentials;
use crate::upstreams::RegistryEntry;

/// The per-call request-body ceiling when the operator sets none: 32 MiB.
///
/// Above any prompt a model API accepts today (a very long context is single
/// digit MiB of text), far below the pod's whole egress ceiling. ADR 0007 B-2:
/// there is no unbounded setting.
pub const DEFAULT_MAX_STREAM_REQUEST_BYTES: u64 = 32 * 1024 * 1024;

/// The per-call reply ceiling when the operator sets none: 64 MiB.
///
/// Download bytes are not charged to the egress ledger, so this is what bounds
/// one call's reply: a streamed model reply is kilobytes to low megabytes.
pub const DEFAULT_MAX_STREAM_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

/// How long the guest may go quiet while uploading a body. Shared with the
/// guest, which orders its own waits against it.
const STREAM_IDLE_TIMEOUT: Duration = nucleus_cred_protocol::stream::UPLOAD_IDLE;

/// How long the upstream may take to answer, and to send each part of its
/// answer. Shared with the guest, which waits longer.
const UPSTREAM_IDLE_TIMEOUT: Duration = nucleus_cred_protocol::stream::UPSTREAM_IDLE;

/// How long a refused stream's remaining upload is read and discarded, so the
/// guest finishes writing and reads the refusal instead of a reset.
const DRAIN_AFTER_REFUSAL: Duration = Duration::from_secs(2);

/// How long a seen nonce is remembered.
pub const STREAM_NONCE_TTL_SECS: u64 = 600;

/// Most nonces one pod's memory holds. A guest reaching it within the TTL is
/// refused rather than having old nonces evicted (eviction would re-admit a
/// replay at exactly the moment the pod is busiest).
pub const STREAM_NONCE_CAPACITY: usize = 4096;

/// Per-call size bounds on a streamed call. ADR 0007 B: finite, and a zero
/// bound is a configuration error rather than "nothing allowed" or
/// "unbounded".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamLimits {
    max_request_bytes: u64,
    max_response_bytes: u64,
}

impl StreamLimits {
    /// The defaults: [`DEFAULT_MAX_STREAM_REQUEST_BYTES`] and
    /// [`DEFAULT_MAX_STREAM_RESPONSE_BYTES`]. Production builds its bounds
    /// through [`StreamLimits::new`] from the node's flags, whose defaults
    /// are these.
    #[cfg(test)]
    pub const DEFAULT: StreamLimits = StreamLimits {
        max_request_bytes: DEFAULT_MAX_STREAM_REQUEST_BYTES,
        max_response_bytes: DEFAULT_MAX_STREAM_RESPONSE_BYTES,
    };

    /// Operator-chosen bounds.
    ///
    /// # Errors
    /// Either bound is zero.
    pub fn new(max_request_bytes: u64, max_response_bytes: u64) -> Result<Self, String> {
        if max_request_bytes == 0 || max_response_bytes == 0 {
            return Err(
                "a streamed egress call's per-call maximum must be greater than zero".to_string(),
            );
        }
        Ok(Self {
            max_request_bytes,
            max_response_bytes,
        })
    }

    /// Largest request body one call may upload.
    #[must_use]
    pub const fn max_request_bytes(self) -> u64 {
        self.max_request_bytes
    }

    /// Largest reply one call may relay.
    #[must_use]
    pub const fn max_response_bytes(self) -> u64 {
        self.max_response_bytes
    }
}

/// What claiming a nonce found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceClaim {
    /// Not seen before; now it has been.
    Fresh,
    /// Seen within the TTL: a replayed open frame.
    Seen,
    /// The memory is full of unexpired nonces.
    Full,
}

/// One pod's memory of the stream nonces it has served.
///
/// The open frame is signed, so only the mediating proxy can compose one; this
/// stops a captured frame being sent twice. Per pod, for the listener's life.
#[derive(Debug)]
pub struct StreamNonces {
    seen: Mutex<HashMap<String, u64>>,
}

impl StreamNonces {
    /// An empty memory.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Claim `nonce` at `now_unix`.
    pub fn claim(&self, nonce: &str, now_unix: u64) -> NonceClaim {
        // Poisoned: the memory cannot be trusted, and "no record, go ahead"
        // is the replay this exists to stop.
        let Ok(mut seen) = self.seen.lock() else {
            return NonceClaim::Full;
        };
        seen.retain(|_, at| now_unix.saturating_sub(*at) < STREAM_NONCE_TTL_SECS);
        if seen.contains_key(nonce) {
            return NonceClaim::Seen;
        }
        if seen.len() >= STREAM_NONCE_CAPACITY {
            return NonceClaim::Full;
        }
        seen.insert(nonce.to_string(), now_unix);
        NonceClaim::Fresh
    }
}

/// A streamed call the host is about to make on the guest's behalf.
///
/// As [`crate::broker_perform::UpstreamCall`]: nothing the guest set decides
/// where this goes. `body` yields the guest's chunks as the host admits them,
/// and an `Err` in it aborts the request.
pub struct StreamCall {
    /// Absolute URL, already resolved against the operator's fixed base.
    pub url: String,
    /// Header the credential goes in, from the operator's entry.
    pub header_name: String,
    /// The credential, with its prefix. Never logged.
    pub header_value: String,
    /// The body's media type, as the guest declared it (validated, counted).
    pub content_type: String,
    /// The request body, chunk by chunk.
    pub body: mpsc::Receiver<Result<Vec<u8>, std::io::Error>>,
}

/// What came back, with the body still arriving.
pub struct StreamResponse {
    /// HTTP status.
    pub status: u16,
    /// The upstream's `content-type`, or empty.
    pub content_type: String,
    /// The reply, chunk by chunk. An `Err` is an upstream failure part way.
    pub body: mpsc::Receiver<Result<Vec<u8>, String>>,
}

/// How the host makes a streamed outbound call. Injected for the reason
/// [`crate::broker_transport::UpstreamCaller`] is.
pub type StreamCaller = Arc<
    dyn Fn(
            StreamCall,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<StreamResponse, String>> + Send>,
        > + Send
        + Sync,
>;

/// A caller that cannot call, for a host with no usable HTTP client.
#[must_use]
pub fn refusing_stream_caller() -> StreamCaller {
    Arc::new(|_call: StreamCall| {
        Box::pin(std::future::ready(Err("no upstream client".to_string())))
    })
}

/// The production caller: a streamed `POST` through a shared client.
///
/// Makes no decision, for the reason [`crate::broker_transport::http_caller`]
/// gives: a policy choice below the layer that holds the credential is one
/// nobody reviews.
#[must_use]
pub fn http_stream_caller(client: reqwest::Client) -> StreamCaller {
    Arc::new(move |call: StreamCall| {
        let client = client.clone();
        Box::pin(async move {
            let body =
                reqwest::Body::wrap_stream(tokio_stream::wrappers::ReceiverStream::new(call.body));
            let resp = client
                .post(&call.url)
                .header(&call.header_name, &call.header_value)
                .header(reqwest::header::CONTENT_TYPE, &call.content_type)
                .body(body)
                .send()
                .await
                .map_err(|e| e.to_string())?;
            let status = resp.status().as_u16();
            let content_type = resp
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            // Bounded: the relay below reads one chunk at a time, so an
            // upstream faster than the guest is held to four chunks here.
            let (tx, rx) = mpsc::channel(4);
            tokio::spawn(async move {
                let mut resp = resp;
                loop {
                    let next = match resp.chunk().await {
                        Ok(Some(bytes)) => Ok(bytes.to_vec()),
                        Ok(None) => break,
                        Err(e) => Err(e.to_string()),
                    };
                    let failed = next.is_err();
                    // The relay hung up: stop reading the upstream.
                    if tx.send(next).await.is_err() || failed {
                        break;
                    }
                }
            });
            Ok(StreamResponse {
                status,
                content_type,
                body: rx,
            })
        })
    })
}

/// One pod's streamed-call machinery, held for the listener's life.
pub struct PodStreams {
    /// How to make the call.
    pub caller: StreamCaller,
    /// Per-call bounds.
    pub limits: StreamLimits,
    /// The nonces this pod's streams have used.
    pub nonces: StreamNonces,
}

impl PodStreams {
    /// A pod's streams, with an empty nonce memory.
    #[must_use]
    pub fn new(caller: StreamCaller, limits: StreamLimits) -> Self {
        Self {
            caller,
            limits,
            nonces: StreamNonces::new(),
        }
    }
}

/// Everything the host needs to serve a streamed call for one pod. Every field
/// is per pod, as for [`crate::broker_perform::PerformContext`].
pub struct StreamContext<'a> {
    /// Who is asking, from which socket accepted the connection.
    pub identity: &'a PodIdentity,
    /// This pod's policy.
    pub policy: &'a PermissionLattice,
    /// This pod's credentials.
    pub credentials: &'a PodCredentials,
    /// The upstreams this pod may reach.
    pub upstreams: &'a [RegistryEntry],
    /// This pod's ONE egress balance (#2905).
    pub egress: &'a crate::egress_meter::EgressMeter,
    /// This pod's caller, bounds and nonce memory.
    pub streams: &'a PodStreams,
}

/// Why a stream was refused before its head was granted.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Refusal {
    /// Policy, an unknown name, a path that leaves the base, or no credential.
    /// One reason for all of them, so a guest cannot enumerate which differ.
    NotPermitted,
    /// The guest broke the framing, or went quiet.
    Malformed,
    /// The upstream could not be called, or failed before answering.
    UpstreamFailed,
    /// A refusal whose reason is the guest's own traffic: the egress balance,
    /// the per-call ceiling, a reused nonce. Named, so the remedy is visible.
    Named(String),
}

impl Refusal {
    fn reason(&self) -> String {
        match self {
            Refusal::NotPermitted => "not permitted".to_string(),
            Refusal::Malformed => "malformed request".to_string(),
            Refusal::UpstreamFailed => "upstream call failed".to_string(),
            Refusal::Named(reason) => reason.clone(),
        }
    }
}

/// How the upload half ended.
#[derive(Debug)]
enum PumpStop {
    /// Refused part way, by name. The upstream request was aborted.
    Refused(String),
    /// The guest broke the framing or went quiet. The request was aborted.
    Guest,
    /// The upstream stopped reading (it answered early). Not a refusal.
    UpstreamStoppedReading,
}

/// What one call came to, for its audit record.
struct CallRecord {
    outcome: &'static str,
    reason: String,
    status: u16,
    upload_bytes: u64,
    download_bytes: u64,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A media type the host will put in a request header: visible ASCII and
/// spaces, non-empty. Anything else is a malformed request, refused before an
/// HTTP client gets the chance to refuse it less clearly.
fn header_safe(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| (0x20..0x7f).contains(&b))
}

fn encode_line<T: serde::Serialize>(value: &T) -> String {
    // A serialisation failure must not produce a grant: fall back to a
    // refusal shape, which both reply types can be read as refused from.
    serde_json::to_string(value)
        .unwrap_or_else(|_| r#"{"granted":false,"reason":"internal error"}"#.to_string())
}

/// Serve one streamed call on an accepted, authenticated connection.
///
/// `reader` is positioned just after the open frame; `writer` is the same
/// connection's write half. Every outcome after the open frame leaves an
/// audit record in the pod's `lifecycle.log`.
pub async fn serve_stream<R, W>(
    req: &StreamRequest,
    ctx: &StreamContext<'_>,
    now: u64,
    reader: &mut R,
    writer: &mut W,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let record = run(req, ctx, now, reader, writer).await;
    let detail = serde_json::json!({
        "target": req.target,
        "outcome": record.outcome,
        "reason": record.reason,
        "status": record.status,
        "upload_bytes": record.upload_bytes,
        "download_bytes": record.download_bytes,
    })
    .to_string();
    ctx.egress.record_call(&detail).await;
}

/// Whether the guest may still be sending body chunks when a refusal is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Remaining {
    /// The body has not been read to its end: drain it briefly.
    MayFollow,
    /// The body ended: there is nothing to drain, and waiting would only
    /// delay the refusal.
    Ended,
}

/// Refuse with a head, then (if the guest may still be uploading) read and
/// discard what it sends for a moment, so it reads the refusal rather than a
/// reset.
async fn refuse<R, W>(
    refusal: &Refusal,
    upload_bytes: u64,
    remaining: Remaining,
    reader: &mut R,
    writer: &mut W,
) -> CallRecord
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let reason = refusal.reason();
    let head = StreamHead {
        granted: false,
        reason: reason.clone(),
        status: 0,
        content_type: String::new(),
    };
    let _ = write_line(writer, &encode_line(&head)).await;
    if remaining == Remaining::MayFollow {
        let _ = tokio::time::timeout(DRAIN_AFTER_REFUSAL, async {
            while let Ok(Chunk::Data(_)) = read_chunk(reader).await {}
        })
        .await;
    }
    CallRecord {
        outcome: "refused",
        reason,
        status: 0,
        upload_bytes,
        download_bytes: 0,
    }
}

async fn run<R, W>(
    req: &StreamRequest,
    ctx: &StreamContext<'_>,
    now: u64,
    reader: &mut R,
    writer: &mut W,
) -> CallRecord
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // 1–3. The perform path's own decision, resolution and path fixing.
    let Some(resolved) = crate::broker_perform::resolve(
        &Asked {
            operation: &req.operation,
            target: &req.target,
            justification: &req.justification,
            path: &req.path,
        },
        ctx.identity,
        ctx.policy,
        ctx.upstreams,
        now,
    ) else {
        return refuse(
            &Refusal::NotPermitted,
            0,
            Remaining::MayFollow,
            reader,
            writer,
        )
        .await;
    };
    if !header_safe(&req.content_type) {
        return refuse(&Refusal::Malformed, 0, Remaining::MayFollow, reader, writer).await;
    }

    // 4. A replayed open frame is refused before anything is charged.
    match ctx.streams.nonces.claim(&req.nonce, now) {
        NonceClaim::Fresh => {}
        NonceClaim::Seen => {
            let r = Refusal::Named("stream nonce already used".to_string());
            return refuse(&r, 0, Remaining::MayFollow, reader, writer).await;
        }
        NonceClaim::Full => {
            let r = Refusal::Named("too many streams opened recently".to_string());
            return refuse(&r, 0, Remaining::MayFollow, reader, writer).await;
        }
    }

    // 4b. The open frame's guest-chosen bytes, charged before the mint so an
    //     exhausted pod costs no token exchange (as for a perform).
    let open_bytes =
        u64::try_from(req.path.len().saturating_add(req.content_type.len())).unwrap_or(u64::MAX);
    let open_charge = match ctx.egress.admit(open_bytes, now).await {
        Ok(charge) => charge,
        Err(refusal) => {
            return refuse(
                &Refusal::Named(refusal.to_string()),
                0,
                Remaining::MayFollow,
                reader,
                writer,
            )
            .await;
        }
    };

    // 5–6. Mint and fetch: the perform path's own function.
    let InjectedHeader {
        value: header_value,
        federated,
    } = match crate::broker_perform::credential_header(&resolved, ctx.credentials, now).await {
        Ok(header) => header,
        Err(miss) => {
            open_charge.not_sent();
            let refusal = match miss {
                CredentialMiss::MintFailed => Refusal::UpstreamFailed,
                CredentialMiss::NotHeld => Refusal::NotPermitted,
            };
            return refuse(&refusal, 0, Remaining::MayFollow, reader, writer).await;
        }
    };
    open_charge.sent();

    // 7. Call, with the body pumped from the guest as the ledger admits it.
    let spec = resolved.entry().spec();
    let (tx, rx) = mpsc::channel(4);
    let call = (ctx.streams.caller)(StreamCall {
        url: resolved.url().to_string(),
        header_name: spec.header.clone(),
        header_value,
        content_type: req.content_type.clone(),
        body: rx,
    });
    let mut uploaded: u64 = 0;
    let pump = pump(reader, tx, ctx, &mut uploaded);
    let (pumped, called) = tokio::join!(pump, tokio::time::timeout(UPSTREAM_IDLE_TIMEOUT, call));

    let remaining = match pumped {
        Ok(()) => Remaining::Ended,
        Err(_) => Remaining::MayFollow,
    };
    let refusal = match (&pumped, &called) {
        (Err(PumpStop::Refused(reason)), _) => Some(Refusal::Named(reason.clone())),
        (Err(PumpStop::Guest), _) => Some(Refusal::Malformed),
        (_, Err(_) | Ok(Err(_))) => Some(Refusal::UpstreamFailed),
        (Ok(()) | Err(PumpStop::UpstreamStoppedReading), Ok(Ok(_))) => None,
    };
    if let Some(refusal) = refusal {
        return refuse(&refusal, uploaded, remaining, reader, writer).await;
    }
    let Ok(Ok(mut response)) = called else {
        // Unreachable: every other shape refused above.
        return refuse(
            &Refusal::UpstreamFailed,
            uploaded,
            remaining,
            reader,
            writer,
        )
        .await;
    };

    // The upstream refused a minted token: evict it so the next call mints
    // afresh. Not retried; see `handle_perform`.
    if federated && response.status == 401 {
        ctx.credentials.evict(&spec.name);
        return refuse(
            &Refusal::UpstreamFailed,
            uploaded,
            remaining,
            reader,
            writer,
        )
        .await;
    }

    // 8. Granted: the head, then the reply as it arrives, then the end.
    let head = StreamHead {
        granted: true,
        reason: "granted".to_string(),
        status: response.status,
        content_type: if header_safe(&response.content_type) {
            response.content_type.clone()
        } else {
            String::new()
        },
    };
    let mut record = CallRecord {
        outcome: "granted",
        reason: String::new(),
        status: response.status,
        upload_bytes: uploaded,
        download_bytes: 0,
    };
    if write_line(writer, &encode_line(&head)).await.is_err() {
        record.outcome = "guest_gone";
        return record;
    }
    let max = ctx.streams.limits.max_response_bytes();
    let end = loop {
        let next = tokio::time::timeout(UPSTREAM_IDLE_TIMEOUT, response.body.recv()).await;
        let bytes = match next {
            Ok(None) => {
                break StreamEnd {
                    complete: true,
                    reason: String::new(),
                };
            }
            Ok(Some(Ok(bytes))) => bytes,
            Ok(Some(Err(_))) => {
                break StreamEnd {
                    complete: false,
                    reason: "upstream call failed".to_string(),
                };
            }
            Err(_) => {
                break StreamEnd {
                    complete: false,
                    reason: format!(
                        "the upstream sent nothing for {}s",
                        UPSTREAM_IDLE_TIMEOUT.as_secs()
                    ),
                };
            }
        };
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let room = max.saturating_sub(record.download_bytes);
        let over = len > room;
        let keep = usize::try_from(room.min(len)).unwrap_or(bytes.len());
        if write_chunks(writer, &bytes[..keep]).await.is_err() {
            record.outcome = "guest_gone";
            return record;
        }
        record.download_bytes = record
            .download_bytes
            .saturating_add(u64::try_from(keep).unwrap_or(u64::MAX));
        if over {
            break StreamEnd {
                complete: false,
                reason: format!(
                    "the reply exceeds this node's per-call maximum of {max} bytes \
                     (--egress-stream-max-response-bytes)"
                ),
            };
        }
    };
    // Dropping the receiver stops the upstream read when the reply was cut.
    drop(response);
    if !end.complete {
        record.outcome = "truncated";
        record.reason.clone_from(&end.reason);
    }
    let _ = write_end(writer).await;
    let _ = write_line(writer, &encode_line(&end)).await;
    record
}

/// The upload half: read the guest's chunks, charge each to the pod's ONE
/// egress balance, and only then hand it to the upstream request.
///
/// On a refusal or a framing failure, an `Err` is sent into the request body
/// so the HTTP client aborts the request rather than completing a truncated
/// one the upstream might act on.
async fn pump<R>(
    reader: &mut R,
    tx: mpsc::Sender<Result<Vec<u8>, std::io::Error>>,
    ctx: &StreamContext<'_>,
    uploaded: &mut u64,
) -> Result<(), PumpStop>
where
    R: AsyncRead + Unpin,
{
    let stop = loop {
        let chunk = match tokio::time::timeout(STREAM_IDLE_TIMEOUT, read_chunk(reader)).await {
            Ok(Ok(chunk)) => chunk,
            Ok(Err(_)) | Err(_) => break PumpStop::Guest,
        };
        let data = match chunk {
            // The whole body arrived and was forwarded: dropping `tx` ends
            // the request body cleanly.
            Chunk::End => return Ok(()),
            Chunk::Data(data) => data,
        };
        let len = u64::try_from(data.len()).unwrap_or(u64::MAX);
        let max = ctx.streams.limits.max_request_bytes();
        if uploaded.saturating_add(len) > max {
            break PumpStop::Refused(format!(
                "the request body exceeds this node's per-call maximum of {max} bytes \
                 (--egress-stream-max-request-bytes)"
            ));
        }
        // Charged BEFORE it is forwarded: a refused chunk never leaves.
        let charge = match ctx.egress.admit(len, now_unix()).await {
            Ok(charge) => charge,
            Err(refusal) => break PumpStop::Refused(refusal.to_string()),
        };
        if tx.send(Ok(data)).await.is_err() {
            // The request is gone, so these bytes provably were not sent.
            charge.not_sent();
            return Err(PumpStop::UpstreamStoppedReading);
        }
        // Handed to the client: sent, or may have been (ambiguous is sent).
        charge.sent();
        *uploaded = uploaded.saturating_add(len);
    };
    let _ = tx
        .send(Err(std::io::Error::other("the host stopped this upload")))
        .await;
    Err(stop)
}

#[cfg(test)]
mod tests {
    //! The host half of #2696 P4, driven over the REAL serving path
    //! (`serve_connection_with_timeout`, the function the listener runs per
    //! connection) by a guest that speaks the shared codec, against a fake
    //! upstream that is a real HTTP server. Nothing here is vendor-specific:
    //! the upstream is a generic SSE endpoint and the credential is a
    //! placeholder.

    use super::*;
    use crate::broker_perform::IdempotencyLedger;
    use crate::broker_transport::{BrokerServing, refusing_caller, serve_connection_with_timeout};
    use nucleus_cred_broker::{Credential, CredentialStore};
    use nucleus_cred_protocol::stream::MAX_STREAM_LINE_BYTES;
    use nucleus_cred_protocol::stream::io::read_line;
    use tokio::io::{AsyncWriteExt, BufReader};
    use tokio_stream::StreamExt;

    const KEY: &[u8] = b"test-broker-capability";
    const TOKEN: &str = "test-token-123";
    const MIB: usize = 1024 * 1024;

    /// The events the fake upstream streams back, in order.
    const EVENTS: [&str; 3] = [
        "event: delta\ndata: {\"text\":\"hel\"}\n\n",
        "event: delta\ndata: {\"text\":\"lo\"}\n\n",
        "event: done\ndata: {}\n\n",
    ];

    /// What the fake upstream saw of one request.
    #[derive(Debug, Clone)]
    struct Seen {
        authorization: Option<String>,
        content_type: Option<String>,
        body_len: usize,
        /// Whether the request body arrived whole. An aborted upload is not.
        complete: bool,
    }

    type Log = Arc<Mutex<Vec<Seen>>>;

    async fn handle(
        axum::extract::State(log): axum::extract::State<Log>,
        headers: axum::http::HeaderMap,
        body: axum::body::Body,
    ) -> axum::response::Response {
        let mut data = body.into_data_stream();
        let mut body_len = 0;
        let mut complete = true;
        while let Some(part) = data.next().await {
            match part {
                Ok(bytes) => body_len += bytes.len(),
                Err(_) => {
                    complete = false;
                    break;
                }
            }
        }
        let header = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        log.lock().expect("log").push(Seen {
            authorization: header("authorization"),
            content_type: header("content-type"),
            body_len,
            complete,
        });
        let (tx, rx) = mpsc::channel::<Result<Vec<u8>, std::convert::Infallible>>(4);
        tokio::spawn(async move {
            for event in EVENTS {
                tokio::time::sleep(Duration::from_millis(20)).await;
                if tx.send(Ok(event.as_bytes().to_vec())).await.is_err() {
                    return;
                }
            }
        });
        axum::response::Response::builder()
            .status(200)
            .header("content-type", "text/event-stream")
            .body(axum::body::Body::from_stream(
                tokio_stream::wrappers::ReceiverStream::new(rx),
            ))
            .expect("response")
    }

    /// A real HTTP server on loopback: reads the whole body, records what it
    /// saw, and answers with three server-sent events sent 20 ms apart.
    async fn upstream() -> (String, Log) {
        let log: Log = Arc::new(Mutex::new(Vec::new()));
        let app = axum::Router::new()
            .route("/v1/complete", axum::routing::post(handle))
            .with_state(Arc::clone(&log));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move { axum::serve(listener, app).await });
        (format!("http://{addr}/v1"), log)
    }

    /// One pod, as the listener would hold it.
    struct Pod {
        identity: PodIdentity,
        policy: PermissionLattice,
        credentials: PodCredentials,
        upstreams: Vec<RegistryEntry>,
        ledger: IdempotencyLedger,
        egress: Arc<crate::egress_meter::EgressMeter>,
        streams: PodStreams,
        dir: tempfile::TempDir,
    }

    impl Pod {
        fn new(base: &str, ceiling: u64, limits: StreamLimits) -> Self {
            Self::holding(base, ceiling, limits, &["model-api"])
        }

        /// A pod whose store holds a credential under each of `held`, whether
        /// or not the operator configured an upstream of that name.
        fn holding(base: &str, ceiling: u64, limits: StreamLimits, held: &[&str]) -> Self {
            // `main` installs this before any client exists; reqwest is built
            // with `rustls-no-provider`, so `Client::new()` panics without it.
            let _ = rustls::crypto::ring::default_provider().install_default();
            let mut store = CredentialStore::new();
            for name in held {
                store.insert(*name, Credential::new(TOKEN));
            }
            let dir = tempfile::tempdir().expect("tempdir");
            Self {
                identity: PodIdentity::observed_by_host("spiffe://nucleus/pod/stream"),
                policy: PermissionLattice::permissive(),
                credentials: PodCredentials::static_only(store),
                upstreams: vec![RegistryEntry::env(nucleus_spec::CredentialedEgressSpec {
                    name: "model-api".into(),
                    upstream: base.to_string(),
                    credential_env: "LLM_API_TOKEN".into(),
                    header: "authorization".into(),
                    value_prefix: "Bearer ".into(),
                })],
                ledger: IdempotencyLedger::new(),
                egress: crate::egress_meter::EgressMeter::new(
                    portcullis::EgressCeiling::new(ceiling, portcullis::EgressPace::Unpaced),
                    dir.path().to_path_buf(),
                    "pod-stream".to_string(),
                ),
                streams: PodStreams::new(http_stream_caller(reqwest::Client::new()), limits),
                dir,
            }
        }

        fn serving(&self) -> BrokerServing<'_> {
            BrokerServing {
                identity: &self.identity,
                policy: &self.policy,
                credentials: &self.credentials,
                broker_secret: Some(KEY),
                upstreams: &self.upstreams,
                ledger: &self.ledger,
                egress: &self.egress,
                upstream_caller: refusing_caller(),
                streams: &self.streams,
            }
        }

        fn audit(&self) -> String {
            std::fs::read_to_string(self.dir.path().join("lifecycle.log")).unwrap_or_default()
        }
    }

    fn open(target: &str, nonce: &str) -> StreamRequest {
        StreamRequest {
            operation: "WebFetch".into(),
            target: target.into(),
            justification: "credentialed egress".into(),
            nonce: nonce.into(),
            path: "/complete".into(),
            content_type: "application/json".into(),
        }
    }

    /// What the guest read back.
    #[derive(Debug)]
    struct Heard {
        head: StreamHead,
        body: Vec<u8>,
        end: Option<StreamEnd>,
        /// Every byte the guest received, for the credential scan.
        raw: String,
    }

    /// Be the guest: send the signed open frame and `body` as chunks, and read
    /// the head, the reply and its end, all over the real serving path.
    async fn drive(pod: &Pod, req: &StreamRequest, body: &[u8]) -> Heard {
        let open_line = format!(
            "{}\n",
            nucleus_cred_protocol::frame::sign(KEY, &serde_json::to_string(req).expect("json"))
        );
        let (client, server) = tokio::io::duplex(256 * 1024);
        let serving = pod.serving();
        let serve = serve_connection_with_timeout(server, &serving, Duration::from_secs(10));
        let (r, mut w) = tokio::io::split(client);
        let upload = async move {
            // Write errors are expected once the host refuses and hangs up.
            if w.write_all(open_line.as_bytes()).await.is_ok()
                && write_chunks(&mut w, body).await.is_ok()
            {
                let _ = write_end(&mut w).await;
            }
        };
        let listen = async move {
            let mut r = BufReader::new(r);
            let head_line = read_line(&mut r, MAX_STREAM_LINE_BYTES)
                .await
                .expect("a head");
            let head: StreamHead = serde_json::from_str(&head_line).expect("a head");
            let mut raw = head_line.clone();
            let mut got = Vec::new();
            let mut end = None;
            if head.granted {
                while let Chunk::Data(d) = read_chunk(&mut r).await.expect("a chunk") {
                    got.extend(d);
                }
                let end_line = read_line(&mut r, MAX_STREAM_LINE_BYTES)
                    .await
                    .expect("an end");
                raw.push_str(&end_line);
                end = Some(serde_json::from_str(&end_line).expect("an end"));
            }
            raw.push_str(&String::from_utf8_lossy(&got));
            Heard {
                head,
                body: got,
                end,
                raw,
            }
        };
        let ((), (), heard) = tokio::join!(serve, upload, listen);
        heard
    }

    fn mebibyte() -> Vec<u8> {
        (0..MIB).map(|i| b"0123456789abcdef"[i % 16]).collect()
    }

    /// **#2696 P4's headline.** A 1 MiB request body streams through the host
    /// to the upstream, and the upstream's server-sent events stream back, in
    /// order and whole. The host injected the credential: the upstream saw
    /// it, and not one byte the guest received carries it.
    ///
    /// Red on main: there is no stream ask, so this open frame is read as a
    /// malformed query, and the only body-carrying frame (a perform) is
    /// refused above 256 KiB.
    #[tokio::test]
    async fn a_mebibyte_request_streams_up_and_an_sse_reply_streams_back() {
        let (base, seen) = upstream().await;
        let pod = Pod::new(&base, 1 << 30, StreamLimits::DEFAULT);
        let heard = drive(&pod, &open("model-api", "n-1"), &mebibyte()).await;

        assert!(heard.head.granted, "{:?}", heard.head);
        assert_eq!(heard.head.status, 200);
        assert_eq!(heard.head.content_type, "text/event-stream");
        assert_eq!(
            String::from_utf8(heard.body).expect("utf-8"),
            EVENTS.concat()
        );
        assert_eq!(
            heard.end,
            Some(StreamEnd {
                complete: true,
                reason: String::new()
            })
        );

        let seen = seen.lock().expect("log").clone();
        assert_eq!(seen.len(), 1, "exactly one upstream call: {seen:?}");
        assert!(seen[0].complete, "the upload arrived whole");
        assert_eq!(seen[0].body_len, MIB);
        assert_eq!(
            seen[0].authorization.as_deref(),
            Some("Bearer test-token-123"),
            "the HOST injected the credential"
        );
        assert_eq!(seen[0].content_type.as_deref(), Some("application/json"));
        assert!(
            !heard.raw.contains(TOKEN),
            "the credential reached the guest: {}",
            heard.raw
        );

        // Charged to the pod's ONE ledger: the body plus the open frame's
        // guest-chosen bytes.
        assert!(pod.egress.counted() >= u64::try_from(MIB).expect("fits"));
        let audit = pod.audit();
        assert!(
            audit.contains("egress_stream_call") && audit.contains(r#"\"outcome\":\"granted\""#),
            "every call leaves a record: {audit}"
        );
        assert!(
            !audit.contains(TOKEN),
            "nor does the record carry the credential"
        );
    }

    /// **Exhaustion mid-stream is refused by name**, and the chunk that would
    /// pass the ceiling is never forwarded: the upstream sees an aborted
    /// request, never a whole one.
    #[tokio::test]
    async fn egress_exhaustion_mid_upload_is_refused_by_name() {
        let (base, seen) = upstream().await;
        let ceiling = 200 * 1024;
        let pod = Pod::new(&base, ceiling, StreamLimits::DEFAULT);
        let heard = drive(&pod, &open("model-api", "n-1"), &mebibyte()).await;

        assert!(!heard.head.granted);
        assert!(
            heard
                .head
                .reason
                .contains("egress budget exhausted (egress.max_bytes)"),
            "the refusal names its dimension: {}",
            heard.head.reason
        );
        assert!(
            pod.egress.counted() <= ceiling,
            "nothing past the ceiling was charged"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        for call in seen.lock().expect("log").iter() {
            assert!(!call.complete, "the upstream got a whole request: {call:?}");
            assert!(u64::try_from(call.body_len).expect("fits") <= ceiling);
        }
        assert!(pod.audit().contains("egress_budget_exhausted"));
    }

    /// **A name the operator did not configure is refused**, with the policy
    /// refusal's reason, and no upstream is called.
    #[tokio::test]
    async fn an_undeclared_upstream_is_refused() {
        let (base, seen) = upstream().await;
        // The store DOES hold a credential under the undeclared name, so the
        // refusal below is the registry's (`resolve`), not the store's: the
        // store keys by name too, and would otherwise refuse on its own and
        // leave the name check untested.
        let pod = Pod::holding(
            &base,
            1 << 30,
            StreamLimits::DEFAULT,
            &["model-api", "not-configured"],
        );
        let heard = drive(&pod, &open("not-configured", "n-1"), b"{}").await;
        assert!(!heard.head.granted);
        assert_eq!(heard.head.reason, "not permitted");
        assert!(
            seen.lock().expect("log").is_empty(),
            "no upstream was called"
        );

        // Non-vacuity: the configured name on the same pod is served.
        let heard = drive(&pod, &open("model-api", "n-2"), b"{}").await;
        assert!(heard.head.granted, "{:?}", heard.head);
    }

    /// A captured open frame cannot be sent twice.
    #[tokio::test]
    async fn a_replayed_open_frame_is_refused() {
        let (base, seen) = upstream().await;
        let pod = Pod::new(&base, 1 << 30, StreamLimits::DEFAULT);
        assert!(
            drive(&pod, &open("model-api", "once"), b"{}")
                .await
                .head
                .granted
        );
        let again = drive(&pod, &open("model-api", "once"), b"{}").await;
        assert!(!again.head.granted);
        assert_eq!(again.head.reason, "stream nonce already used");
        assert_eq!(seen.lock().expect("log").len(), 1);
    }

    /// The per-call request ceiling refuses by name before the upstream gets a
    /// whole request.
    #[tokio::test]
    async fn a_request_past_the_per_call_maximum_is_refused_by_name() {
        let (base, seen) = upstream().await;
        let limits =
            StreamLimits::new(256 * 1024, DEFAULT_MAX_STREAM_RESPONSE_BYTES).expect("limits");
        let pod = Pod::new(&base, 1 << 30, limits);
        let heard = drive(&pod, &open("model-api", "n-1"), &mebibyte()).await;
        assert!(!heard.head.granted);
        assert!(
            heard
                .head
                .reason
                .contains("per-call maximum of 262144 bytes"),
            "{}",
            heard.head.reason
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(seen.lock().expect("log").iter().all(|c| !c.complete));
    }

    /// A reply past the per-call ceiling is cut and the END says why, so a
    /// truncated reply is never mistaken for a short one.
    #[tokio::test]
    async fn a_reply_past_the_per_call_maximum_is_cut_and_named() {
        let (base, _seen) = upstream().await;
        let limits = StreamLimits::new(DEFAULT_MAX_STREAM_REQUEST_BYTES, 10).expect("limits");
        let pod = Pod::new(&base, 1 << 30, limits);
        let heard = drive(&pod, &open("model-api", "n-1"), b"{}").await;
        assert!(heard.head.granted);
        assert_eq!(heard.body.len(), 10);
        let end = heard.end.expect("an end");
        assert!(!end.complete);
        assert!(
            end.reason.contains("per-call maximum of 10 bytes"),
            "{}",
            end.reason
        );
        assert!(pod.audit().contains("truncated"));
    }

    /// A zero bound is a configuration error, never "nothing" or "unbounded".
    #[test]
    fn a_zero_per_call_bound_is_refused() {
        assert!(StreamLimits::new(0, 1).is_err());
        assert!(StreamLimits::new(1, 0).is_err());
        assert!(StreamLimits::new(1, 1).is_ok());
    }

    /// A nonce memory that is full refuses rather than evicting.
    #[test]
    fn a_full_nonce_memory_refuses() {
        let nonces = StreamNonces::new();
        for i in 0..STREAM_NONCE_CAPACITY {
            assert_eq!(nonces.claim(&format!("n{i}"), 0), NonceClaim::Fresh);
        }
        assert_eq!(nonces.claim("one-more", 0), NonceClaim::Full);
        assert_eq!(nonces.claim("n0", 0), NonceClaim::Seen);
        // Past the TTL the memory empties and the nonce is fresh again.
        assert_eq!(nonces.claim("n0", STREAM_NONCE_TTL_SECS), NonceClaim::Fresh);
    }
}
