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
//! The signed OPEN is followed by bounded chunks. The host stages the complete
//! upload in an anonymous temporary file, bounded by [`StreamLimits`], and hashes
//! the bytes it owns. It then applies the same host policy and action-bound
//! approval mechanism as PERFORM, reserves the full egress charge, retrieves the
//! credential, and rechecks current policy before committing the effect.
//! The HTTP body consumes the shared rate allowance as it yields staged slices;
//! the total reservation stays owned until the body is dropped. The upload and
//! response-head deadline also bounds time spent waiting for rate windows.
//!
//! Allowed uploads keep only chunks in memory. Approval-gated uploads retain
//! their full payload under the per-pod review limit. The file is removed on close, including
//! refusal and cancellation. The upstream sees nothing before staging and host
//! authorization finish. Request streaming therefore incurs local disk I/O and
//! waits for upload completion; response streaming, including SSE, is preserved.
//!
//! The decision includes actual WebFetch authority and the guest's declared
//! operation. Trusted mappings of remote API semantics, revocation, and runtime
//! cost settlement remain separate work. Download bytes are not charged by the
//! upload-only egress ledger; [`StreamLimits`] bounds each response.

mod staged;
pub(crate) mod staging_budget;

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

mod upload;

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
/// where this goes. `body` yields the authorized file's chunks,
/// and an `Err` in it aborts the request.
pub struct StreamCall {
    _permit: crate::host_decide::effects::ExecutingEffect,
    /// Absolute URL, already resolved against the operator's fixed base.
    pub url: String,
    /// Header the credential goes in, from the operator's entry.
    pub header_name: String,
    /// The credential, with its prefix. Never logged.
    pub header_value: String,
    /// The body's media type, as the guest declared it (validated, counted).
    pub content_type: String,
    /// The request body, chunk by chunk.
    pub body: upload::UploadBody,
}

/// What came back, with the body still arriving.
pub struct StreamResponse {
    /// HTTP status.
    pub status: u16,
    /// The upstream's `content-type`, or empty.
    pub content_type: String,
    /// The reply, chunk by chunk. An `Err` is an upstream failure part way.
    pub body: ResponseBody,
}

/// The response reader belongs to the serving future. Dropping the request
/// drops its HTTP response rather than leaving a detached reader waiting on it.
pub enum ResponseBody {
    Http(reqwest::Response),
    #[cfg(test)]
    Channel(mpsc::Receiver<Result<ResponseChunk, String>>),
}

impl ResponseBody {
    async fn recv(&mut self) -> Option<Result<ResponseChunk, String>> {
        match self {
            Self::Http(response) => Some(match response.chunk().await {
                Ok(Some(bytes)) => Ok(ResponseChunk::Data(bytes.to_vec())),
                Ok(None) => Ok(ResponseChunk::End),
                Err(error) => Err(error.to_string()),
            }),
            #[cfg(test)]
            Self::Channel(receiver) => receiver.recv().await,
        }
    }
}

pub enum ResponseChunk {
    Data(Vec<u8>),
    /// The upstream reader observed EOF; channel closure alone is not evidence.
    End,
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
            let body = reqwest::Body::wrap_stream(call.body);
            let resp = client
                .request(crate::broker_perform::effect::METHOD, &call.url)
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
            Ok(StreamResponse {
                status,
                content_type,
                body: ResponseBody::Http(resp),
            })
        })
    })
}

/// One pod's streamed-call machinery, held for the listener's life.
pub struct PodStreams {
    staging: staging_budget::Budget,
    /// How to make the call.
    pub caller: StreamCaller,
    /// Per-call bounds.
    pub limits: StreamLimits,
    /// The nonces this pod's streams have used.
    pub nonces: StreamNonces,
}

impl PodStreams {
    /// A pod's streams, with an empty nonce memory.
    #[cfg(test)]
    pub fn new(caller: StreamCaller, limits: StreamLimits) -> Self {
        Self::with_staging(
            caller,
            limits,
            staging_budget::Budget::new(staging_budget::DEFAULT_BYTES).unwrap(),
        )
    }

    pub(crate) fn with_staging(
        caller: StreamCaller,
        limits: StreamLimits,
        staging: staging_budget::Budget,
    ) -> Self {
        Self {
            staging,
            caller,
            limits,
            nonces: StreamNonces::new(),
        }
    }
}

/// Everything the host needs to serve a streamed call for one pod. Every field
/// is per pod, as for [`crate::broker_perform::PerformContext`].
pub struct StreamContext<'a> {
    /// The pod authority's shared host policy history.
    pub host_policy: &'a crate::host_decide::SharedPodPolicy,

    /// Who is asking, from which socket accepted the connection.
    pub identity: &'a PodIdentity,
    /// This pod's policy.
    pub policy: &'a PermissionLattice,
    /// This pod's credentials.
    pub credentials: &'a PodCredentials,
    /// The upstreams this pod may reach.
    pub upstreams: &'a [RegistryEntry],
    /// This pod's ONE egress balance (#2905).
    pub egress: &'a Arc<crate::egress_meter::EgressMeter>,
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

/// What one call came to, for its audit record.
struct CallRecord {
    outcome: &'static str,
    reason: String,
    status: u16,
    upload_bytes: u64,
    download_bytes: u64,
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
    if crate::host_decide::PodPolicy::available(ctx.host_policy).is_err() {
        return refuse(
            &Refusal::Named("host policy unavailable".into()),
            0,
            Remaining::MayFollow,
            reader,
            writer,
        )
        .await;
    }
    let asked = Asked {
        operation: &req.operation,
        target: &req.target,
        justification: &req.justification,
        path: &req.path,
    };
    let Some(resolved) =
        crate::broker_perform::resolve(&asked, ctx.identity, ctx.policy, ctx.upstreams, now)
    else {
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

    let call_charge = match resolved.entry().call_charge() {
        Ok(charge) => charge,
        Err(reason) => {
            return refuse(
                &Refusal::Named(reason.into()),
                0,
                Remaining::MayFollow,
                reader,
                writer,
            )
            .await;
        }
    };
    // No credentials or upstream I/O until the complete bounded upload is owned.
    let started = std::time::Instant::now();
    let mut staged = match staged::StagedBody::read(
        reader,
        ctx.streams.limits.max_request_bytes(),
        &ctx.streams.staging,
    )
    .await
    {
        Ok(body) => body,
        Err(reason) => return refuse(&reason, 0, Remaining::MayFollow, reader, writer).await,
    };
    let current_time = || {
        let elapsed = started.elapsed();
        now.saturating_add(elapsed.as_secs())
            .saturating_add(u64::from(elapsed.subsec_nanos() != 0))
    };
    let mut effect_request = crate::broker_perform::effect::describe_body(
        &req.operation,
        &resolved,
        &req.content_type,
        staged.digest(),
        staged.len(),
    );
    effect_request.require_approval = req.require_approval;
    let effect = match effect_request.digest() {
        Ok(effect) => nucleus_decision_protocol::ArgsDigest::new(effect),
        Err(_) => return refuse(&Refusal::NotPermitted, 0, Remaining::Ended, reader, writer).await,
    };
    let preflight = || match ctx.host_policy.lock() {
        Ok(mut policy) => match crate::broker::parse_operation(&req.operation) {
            Some(op) => policy.preflight_effect(
                effect,
                op,
                resolved.url(),
                current_time(),
                call_charge,
                req.require_approval,
            ),
            None => Err("unknown operation".into()),
        },
        Err(_) => Err("host policy unavailable".into()),
    };
    if let Err(reason) = preflight() {
        let review = capture_review(
            ctx.host_policy,
            req,
            &resolved,
            &mut staged,
            effect,
            current_time(),
        )
        .await;
        let pause = match review {
            Err(error) => Err(error),
            Ok(()) if req.approval_wait_seconds == 0 => Err(reason),
            Ok(()) => {
                use tokio::io::AsyncReadExt as _;
                let mut extra = [0u8; 1];
                tokio::select! {
                    result = crate::host_decide::effects::wait::for_effect(ctx.host_policy, effect, current_time(), req.approval_wait_seconds) => match result {
                        Ok(crate::host_decide::effects::wait::WaitOutcome::Granted) => Ok(()),
                        Ok(crate::host_decide::effects::wait::WaitOutcome::NoPendingApproval) => Err(reason),
                        Err(error) => Err(error),
                    },
                    _ = reader.read(&mut extra) => Err("approval wait ended: guest disconnected or sent unexpected data".into()),
                }
            }
        };
        if let Err(reason) = pause.and_then(|()| preflight()) {
            return refuse(&Refusal::Named(reason), 0, Remaining::Ended, reader, writer).await;
        }
    }
    let uploaded = staged.len();
    let open_bytes = req.path.len().saturating_add(req.content_type.len()) as u64;
    let mut charge = match ctx
        .egress
        .reserve_upload(open_bytes.saturating_add(uploaded))
        .await
    {
        Ok(charge) => charge,
        Err(reason) => {
            return refuse(
                &Refusal::Named(reason.to_string()),
                0,
                Remaining::Ended,
                reader,
                writer,
            )
            .await;
        }
    };
    let upload_deadline = tokio::time::Instant::now() + UPSTREAM_IDLE_TIMEOUT;
    if !matches!(
        tokio::time::timeout_at(
            upload_deadline,
            upload::pace_open(&mut charge, open_bytes, current_time())
        )
        .await,
        Ok(Ok(()))
    ) {
        charge.not_sent();
        return refuse(
            &Refusal::UpstreamFailed,
            0,
            Remaining::Ended,
            reader,
            writer,
        )
        .await;
    }
    // Staging, operator review and pace waits can outlive the credential PDP witness.
    // Re-run its checker (ADR 0007 C-1), never extend a stale grant's expiry.
    // These immutable inputs resolve the same effect; the shared host policy
    // was checked above and is checked again when committing below.
    let Some(resolved) = crate::broker_perform::resolve(
        &asked,
        ctx.identity,
        ctx.policy,
        ctx.upstreams,
        current_time(),
    ) else {
        charge.not_sent();
        return refuse(&Refusal::NotPermitted, 0, Remaining::Ended, reader, writer).await;
    };
    let InjectedHeader {
        value: header_value,
        federated,
    } = match crate::broker_perform::credential_header(&resolved, ctx.credentials, current_time())
        .await
    {
        Ok(header) => header,
        Err(miss) => {
            charge.not_sent();
            let reason = match miss {
                CredentialMiss::MintFailed => Refusal::UpstreamFailed,
                CredentialMiss::NotHeld => Refusal::NotPermitted,
            };
            return refuse(&reason, 0, Remaining::Ended, reader, writer).await;
        }
    };
    // Staging and minting await other work; commit over current shared policy.
    let permit = match ctx.host_policy.lock() {
        Ok(mut policy) => match crate::broker::parse_operation(&req.operation) {
            Some(op) => policy.authorize_effect(
                effect,
                op,
                resolved.url(),
                current_time(),
                call_charge,
                req.require_approval,
            ),
            None => Err("unknown operation".into()),
        },
        Err(_) => Err("host policy unavailable".into()),
    };
    let permit = match permit {
        Ok(permit) => permit,
        Err(reason) => {
            charge.not_sent();
            let reason = capture_review(
                ctx.host_policy,
                req,
                &resolved,
                &mut staged,
                effect,
                current_time(),
            )
            .await
            .err()
            .unwrap_or(reason);
            return refuse(&Refusal::Named(reason), 0, Remaining::Ended, reader, writer).await;
        }
    };
    let spec = resolved.entry().spec();
    let (tx, rx) = mpsc::channel(4);
    use nucleus_spec::host_effect::outcome::Termination;
    let (permit, mut observation) = permit.observe(ctx.host_policy.clone(), current_time());
    // The body owns the charge through HTTP handoff and cancellation.
    let call = (ctx.streams.caller)(StreamCall {
        _permit: permit,
        url: resolved.url().to_string(),
        header_name: spec.header.clone(),
        header_value,
        content_type: req.content_type.clone(),
        body: upload::UploadBody::new(rx, charge, current_time()),
    });
    // One deadline covers both upload and response headers, including a caller
    // which retains but never drains the body channel.
    let result = tokio::time::timeout_at(upload_deadline, async {
        tokio::join!(staged.send(tx), call)
    })
    .await;
    let remaining = Remaining::Ended;
    let Ok((Ok(()), Ok(mut response))) = result else {
        let _ = observation.finish(Termination::TransportFailure);
        return refuse(
            &Refusal::UpstreamFailed,
            uploaded,
            remaining,
            reader,
            writer,
        )
        .await;
    };

    observation.response(response.status);

    // The upstream refused a minted token: evict it so the next call mints
    // afresh. Not retried; see `handle_perform`.
    if federated && response.status == 401 {
        let _ = observation.finish(Termination::ResponseRejected);
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

    // The host records what it is about to deliver, even if the guest omits
    // its observation report. No upstream status, headers or bytes cross first.
    if crate::host_decide::PodPolicy::observe_response(ctx.host_policy, current_time()).is_err() {
        return refuse(
            &Refusal::Named("host policy unavailable".into()),
            uploaded,
            Remaining::Ended,
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
        let _ = observation.finish(Termination::GuestDisconnected);
        return record;
    }
    let max = ctx.streams.limits.max_response_bytes();
    let mut end = loop {
        let next = tokio::time::timeout(UPSTREAM_IDLE_TIMEOUT, response.body.recv()).await;
        let bytes = match next {
            Ok(Some(Ok(ResponseChunk::End))) => {
                observation.body_complete();
                break StreamEnd {
                    complete: true,
                    reason: String::new(),
                };
            }
            Ok(Some(Ok(ResponseChunk::Data(bytes)))) => bytes,
            Ok(Some(Err(_))) | Ok(None) => {
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
        observation.bytes(&bytes);
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let room = max.saturating_sub(record.download_bytes);
        let over = len > room;
        let keep = usize::try_from(room.min(len)).unwrap_or(bytes.len());
        if write_chunks(writer, &bytes[..keep]).await.is_err() {
            record.outcome = "guest_gone";
            let _ = observation.finish(Termination::GuestDisconnected);
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
    let termination = if end.complete {
        Termination::ResponseRead
    } else {
        Termination::ResponseTruncated
    };
    if observation.finish(termination).is_err() {
        end.complete = false;
        end.reason = "host outcome evidence unavailable".into();
    }
    if !end.complete {
        record.outcome = "truncated";
        record.reason.clone_from(&end.reason);
    }
    let _ = write_end(writer).await;
    let _ = write_line(writer, &encode_line(&end)).await;
    record
}

async fn capture_review(
    policy: &crate::host_decide::SharedPodPolicy,
    request: &nucleus_cred_protocol::StreamRequest,
    resolved: &crate::broker_perform::Resolved<'_>,
    staged: &mut staged::StagedBody,
    effect: nucleus_decision_protocol::ArgsDigest,
    now: u64,
) -> Result<(), String> {
    let needed = policy
        .lock()
        .map_err(|_| "host policy unavailable")?
        .review_requested(effect, now);
    if !needed {
        return Ok(());
    }
    let mut metadata = crate::broker_perform::effect::describe_body(
        &request.operation,
        resolved,
        &request.content_type,
        staged.digest(),
        staged.len(),
    );
    metadata.require_approval = request.require_approval;
    let body = match staged.review_bytes().await {
        Ok(body) => body,
        Err(error) => {
            policy
                .lock()
                .map_err(|_| "host policy unavailable")?
                .refuse_missing_review(effect);
            return Err(error);
        }
    };
    policy
        .lock()
        .map_err(|_| "host policy unavailable")?
        .attach_review(effect, metadata, &body, now)
}

#[cfg(test)]
mod tests {
    //! The host half of #2696 P4, driven over the REAL serving path
    //! (`serve_connection_with_timeout`, the function the listener runs per
    //! connection) by a guest that speaks the shared codec, against a fake
    //! upstream that is a real HTTP server. Nothing here is vendor-specific:
    //! the upstream is a generic SSE endpoint and the credential is a
    //! placeholder.

    mod approval_wait;
    mod paced;

    use super::*;
    use crate::broker_perform::IdempotencyLedger;
    use crate::broker_transport::{BrokerServing, refusing_caller, serve_connection_with_timeout};
    use nucleus_cred_broker::{Credential, CredentialStore};
    use nucleus_cred_protocol::stream::MAX_STREAM_LINE_BYTES;
    use nucleus_cred_protocol::stream::io::read_line;
    use sha2::{Digest, Sha256};
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
        body_sha256: [u8; 32],
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
        let mut hash = Sha256::new();
        let mut complete = true;
        while let Some(part) = data.next().await {
            match part {
                Ok(bytes) => {
                    body_len += bytes.len();
                    hash.update(&bytes);
                }
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
            body_sha256: hash.finalize().into(),
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
        host_policy: crate::host_decide::SharedPodPolicy,
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
                host_policy: crate::host_decide::test_policy(PermissionLattice::permissive()),
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
                host_policy: &self.host_policy,
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
            require_approval: false,
            approval_wait_seconds: 0,
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
        drive_before_end(pod, req, body, || {}).await
    }

    async fn drive_before_end(
        pod: &Pod,
        req: &StreamRequest,
        body: &[u8],
        before_end: impl FnOnce(),
    ) -> Heard {
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
                before_end();
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

    #[tokio::test]
    async fn streamed_calls_debit_the_same_operator_tariff_budget() {
        let (base, seen) = upstream().await;
        let mut pod = Pod::new(&base, 1 << 30, StreamLimits::DEFAULT);
        pod.policy.budget.max_cost_usd = rust_decimal::Decimal::ONE;
        pod.host_policy = crate::host_decide::test_policy(pod.policy.clone());
        pod.upstreams = pod
            .upstreams
            .into_iter()
            .map(|entry| entry.with_call_charge(1_000_000))
            .collect();
        let first = drive(&pod, &open("model-api", "paid"), b"request").await;
        assert!(first.head.granted);
        let second = drive(&pod, &open("model-api", "exhausted"), b"request").await;
        assert!(!second.head.granted);
        assert!(second.head.reason.contains("budget exhausted"));
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn streamed_outcomes_are_host_signed_and_distinguish_truncation() {
        use nucleus_spec::host_effect::{self, outcome};
        for truncated in [false, true] {
            let (base, _) = upstream().await;
            let limits = if truncated {
                StreamLimits::new(1024, 2).unwrap()
            } else {
                StreamLimits::DEFAULT
            };
            let mut pod = Pod::new(&base, 1 << 30, limits);
            let key = ed25519_dalek::SigningKey::from_bytes(&[37; 32]);
            let evidence = crate::host_decide::evidence::Evidence::create(
                uuid::Uuid::new_v4(),
                pod.dir.path(),
                Arc::new(key.clone()),
            )
            .unwrap();
            pod.host_policy = crate::host_decide::PodPolicy::new(
                portcullis::kernel::Kernel::new(pod.policy.clone()),
                evidence,
            );
            let heard = drive(&pod, &open("model-api", "observed"), b"request").await;
            assert!(heard.head.granted);
            assert_eq!(heard.end.unwrap().complete, !truncated);
            let record: outcome::SignedOutcome = serde_json::from_str(
                std::fs::read_to_string(pod.dir.path().join(outcome::LOG_FILE))
                    .unwrap()
                    .trim(),
            )
            .unwrap();
            let auth: host_effect::SignedAuthorization = serde_json::from_str(
                std::fs::read_to_string(pod.dir.path().join(host_effect::LOG_FILE))
                    .unwrap()
                    .trim(),
            )
            .unwrap();
            assert_eq!(
                record.outcome.authorization_record_sha256,
                host_effect::record_hash(&auth).unwrap()
            );
            let response = record.outcome.response.as_ref().unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(response.body_complete, !truncated);
            if truncated {
                assert_eq!(
                    record.outcome.termination,
                    outcome::Termination::ResponseTruncated
                );
                assert!(response.body_bytes > heard.body.len() as u64);
            } else {
                assert_eq!(
                    record.outcome.termination,
                    outcome::Termination::ResponseRead
                );
                assert_eq!(
                    response.body_sha256,
                    hex::encode(Sha256::digest(&heard.body))
                );
            }
            let signature =
                ed25519_dalek::Signature::from_slice(&hex::decode(&record.signature).unwrap())
                    .unwrap();
            key.verifying_key()
                .verify_strict(
                    &outcome::signing_bytes(&record.outcome).unwrap(),
                    &signature,
                )
                .unwrap();
        }
    }

    #[tokio::test]
    async fn cancelled_stream_leaves_an_interrupted_host_outcome() {
        use nucleus_spec::host_effect::outcome;
        let (base, _) = upstream().await;
        let mut pod = Pod::new(&base, 1 << 30, StreamLimits::DEFAULT);
        let evidence = crate::host_decide::evidence::Evidence::create(
            uuid::Uuid::new_v4(),
            pod.dir.path(),
            Arc::new(ed25519_dalek::SigningKey::from_bytes(&[37; 32])),
        )
        .unwrap();
        pod.host_policy = crate::host_decide::PodPolicy::new(
            portcullis::kernel::Kernel::new(pod.policy.clone()),
            evidence,
        );
        let (entered, mut observed) = mpsc::channel(1);
        pod.streams.caller = Arc::new(move |_call| {
            let entered = entered.clone();
            Box::pin(async move {
                entered.send(()).await.unwrap();
                std::future::pending().await
            })
        });
        let request = open("model-api", "cancelled");
        let mut serving = Box::pin(drive(&pod, &request, b"request"));
        tokio::select! {
            _ = &mut serving => panic!("upstream must remain pending"),
            signal = observed.recv() => assert_eq!(signal, Some(())),
        }
        // Drop the actual serving future, rather than inventing a terminal event.
        drop(serving);
        let record: outcome::SignedOutcome = serde_json::from_str(
            std::fs::read_to_string(pod.dir.path().join(outcome::LOG_FILE))
                .unwrap()
                .trim(),
        )
        .unwrap();
        assert_eq!(
            record.outcome.termination,
            outcome::Termination::Interrupted
        );
        assert!(record.outcome.response.is_none());
    }

    #[tokio::test]
    async fn dropping_a_stream_response_closes_the_real_upstream_reader() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let upstream = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                assert_eq!(socket.read(&mut byte).await.unwrap(), 1);
                head.push(byte[0]);
            }
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\nx")
                .await
                .unwrap();
            let mut tail = [0u8; 1024];
            while socket.read(&mut tail).await.unwrap_or(0) != 0 {}
        });
        let policy = crate::host_decide::test_policy(PermissionLattice::permissive());
        let permit = policy
            .lock()
            .unwrap()
            .authorize_effect(
                nucleus_decision_protocol::ArgsDigest::new([1; 32]),
                portcullis::Operation::WebFetch,
                "http://upstream",
                100,
                crate::upstreams::CallCharge::free(),
                false,
            )
            .unwrap();
        let (permit, _observation) = permit.observe(policy.clone(), 100);
        let (tx, rx) = mpsc::channel(1);
        drop(tx);
        let caller = http_stream_caller(reqwest::Client::new());
        let mut response = caller(StreamCall {
            _permit: permit,
            url: format!("http://{address}/call"),
            header_name: "authorization".into(),
            header_value: "test-token".into(),
            content_type: "application/json".into(),
            body: upload::UploadBody::new(
                rx,
                crate::egress_meter::EgressMeter::new(
                    portcullis::EgressCeiling::new(1_000, portcullis::EgressPace::Unpaced),
                    std::env::temp_dir(),
                    "response-owner".into(),
                )
                .reserve_upload(0)
                .await
                .unwrap(),
                100,
            ),
        })
        .await
        .unwrap();
        assert!(matches!(
            response.body.recv().await,
            Some(Ok(ResponseChunk::Data(_)))
        ));
        drop(response);
        tokio::time::timeout(Duration::from_secs(3), upstream)
            .await
            .expect("the upstream reader must not outlive its owner")
            .unwrap();
    }

    #[tokio::test]
    async fn upstream_reader_disappearance_is_not_a_complete_response() {
        let (base, _) = upstream().await;
        let mut pod = Pod::new(&base, 1 << 30, StreamLimits::DEFAULT);
        pod.streams.caller = Arc::new(|mut call| {
            Box::pin(async move {
                while call.body.recv().await.is_some() {}
                let (tx, rx) = mpsc::channel(1);
                drop(tx); // A stopped reader never observed or sent an EOF witness.
                Ok(StreamResponse {
                    status: 200,
                    content_type: String::new(),
                    body: ResponseBody::Channel(rx),
                })
            })
        });
        let heard = drive(&pod, &open("model-api", "reader-gone"), b"request").await;
        assert!(heard.head.granted);
        assert!(!heard.end.unwrap().complete);
    }

    #[tokio::test]
    async fn a_faulted_host_policy_refuses_a_stream_before_upstream_io() {
        let (base, seen) = upstream().await;
        let pod = Pod::new(&base, 1 << 30, StreamLimits::DEFAULT);
        let fault = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = pod.host_policy.lock().unwrap();
            panic!("policy update interrupted");
        }));
        assert!(fault.is_err());
        let heard = drive(&pod, &open("model-api", "after-fault"), b"request").await;
        assert!(!heard.head.granted);
        assert_eq!(heard.head.reason, "host policy unavailable");
        assert!(heard.body.is_empty());
        assert!(seen.lock().unwrap().is_empty());
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
        // The guest never sent an Observe frame. The broker owns this fact.
        let (decision, _token) = pod
            .host_policy
            .lock()
            .unwrap()
            .decide(portcullis::Operation::GitCommit, "commit");
        assert_eq!(
            nucleus_decision_protocol::kernel::outcome_of(&decision.verdict),
            nucleus_decision_protocol::Outcome::Denied {
                reason: nucleus_decision_protocol::DenyReason::FlowRefused,
            }
        );
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
            seen[0].body_sha256,
            <[u8; 32]>::from(Sha256::digest(mebibyte()))
        );
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

    /// Full-upload reservation refuses before any upstream I/O.
    #[tokio::test]
    async fn egress_exhaustion_refuses_the_staged_upload_before_upstream_io() {
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
        assert!(seen.lock().expect("log").is_empty(), "no upstream call");
        assert_eq!(pod.egress.counted(), 0, "unsent bytes are not charged");
        assert!(pod.audit().contains("egress_budget_exhausted"));
    }

    #[tokio::test]
    async fn host_approval_binds_the_complete_stream_and_is_consumed_once() {
        use crate::host_decide::effects::{ApprovalStatus, Operator};
        let (base, seen) = upstream().await;
        let mut pod = Pod::new(&base, 1 << 30, StreamLimits::DEFAULT);
        pod.policy
            .obligations
            .insert(portcullis::Operation::WebFetch);
        pod.host_policy = crate::host_decide::test_policy(pod.policy.clone());
        let req = open("model-api", "request-approval");
        let body = mebibyte();
        let refused = drive(&pod, &req, &body).await;
        assert!(!refused.head.granted);
        assert!(refused.head.reason.starts_with("host approval required:"));
        assert!(seen.lock().unwrap().is_empty());
        assert_eq!(pod.egress.counted(), 0);
        let operator = || Operator::authenticate("operator", "operator").unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let id = {
            let mut policy = pod.host_policy.lock().unwrap();
            let pending = policy.list_effect_approvals(operator(), now);
            assert_eq!(pending.len(), 1);
            let id = pending[0].id;
            let review = policy.effect_review(operator(), id, now).unwrap();
            use base64::Engine as _;
            assert_eq!(
                base64::engine::general_purpose::STANDARD
                    .decode(&review.body_base64)
                    .unwrap(),
                body
            );
            assert_eq!(
                hex::encode(review.request.digest().unwrap()),
                pending[0].effect_sha256
            );
            assert!(!serde_json::to_string(&review).unwrap().contains(TOKEN));
            policy
                .settle_effect_approval(operator(), id, true, now)
                .unwrap();
            id
        };
        // Same OPEN metadata with an altered late payload byte cannot use it.
        let mut changed = body.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(
            !drive(&pod, &open("model-api", "changed-payload"), &changed)
                .await
                .head
                .granted
        );
        let mut content_type = open("model-api", "changed-media");
        content_type.content_type = "text/plain".into();
        assert!(!drive(&pod, &content_type, &body).await.head.granted);
        let mut path = open("model-api", "changed-path");
        path.path = "/different".into();
        assert!(!drive(&pod, &path, &body).await.head.granted);
        assert!(seen.lock().unwrap().is_empty());
        let granted = drive(&pod, &open("model-api", "approved"), &body).await;
        assert!(granted.head.granted, "{:?}", granted.head);
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert!(
            !drive(&pod, &open("model-api", "reused-approval"), &body)
                .await
                .head
                .granted
        );
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert_eq!(
            pod.host_policy
                .lock()
                .unwrap()
                .list_effect_approvals(operator(), now)
                .iter()
                .find(|v| v.id == id)
                .unwrap()
                .status,
            ApprovalStatus::Spent
        );
    }

    #[tokio::test]
    async fn changing_transport_cannot_duplicate_an_approved_effect() {
        use crate::host_decide::effects::Operator;
        let (base, seen) = upstream().await;
        let mut pod = Pod::new(&base, 1 << 30, StreamLimits::DEFAULT);
        pod.policy
            .obligations
            .insert(portcullis::Operation::WebFetch);
        pod.host_policy = crate::host_decide::test_policy(pod.policy.clone());
        let req = open("model-api", "approval-request");
        assert!(!drive(&pod, &req, b"{}").await.head.granted);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let operator = || Operator::authenticate("operator", "operator").unwrap();
        {
            let mut policy = pod.host_policy.lock().unwrap();
            let pending = policy.list_effect_approvals(operator(), now);
            policy
                .settle_effect_approval(operator(), pending[0].id, true, now)
                .unwrap();
        }
        let buffered = nucleus_cred_protocol::PerformRequest {
            operation: req.operation,
            target: req.target,
            justification: req.justification,
            idempotency_key: "buffered-attempt".into(),
            path: req.path,
            body: b"{}".to_vec(),
        };
        let ctx = crate::broker_perform::PerformContext {
            host_policy: &pod.host_policy,
            identity: &pod.identity,
            policy: &pod.policy,
            credentials: &pod.credentials,
            upstreams: &pod.upstreams,
            ledger: &pod.ledger,
            egress: &pod.egress,
        };
        let caller = crate::broker_transport::http_caller(reqwest::Client::new());
        let reply =
            crate::broker_perform::handle_perform(&buffered, &ctx, now, |c| caller(c)).await;
        assert!(reply.granted, "{reply:?}");
        assert_eq!(seen.lock().unwrap().len(), 1);
        assert!(
            !drive(&pod, &open("model-api", "streamed-again"), b"{}")
                .await
                .head
                .granted
        );
        assert_eq!(seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn no_upstream_call_precedes_upload_end_and_late_taint_is_enforced() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (base, seen) = upstream().await;
        let mut pod = Pod::new(&base, 1 << 30, StreamLimits::DEFAULT);
        let calls = Arc::new(AtomicUsize::new(0));
        let invoked = calls.clone();
        let caller = pod.streams.caller.clone();
        pod.streams.caller = Arc::new(move |call| {
            invoked.fetch_add(1, Ordering::SeqCst);
            caller(call)
        });
        let mut req = open("model-api", "late-taint");
        req.operation = "GitCommit".into();
        // More than the duplex capacity: completing this upload requires the
        // host to read it, so the assertion cannot pass just from no scheduling.
        let heard = drive_before_end(&pod, &req, &mebibyte(), || {
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            crate::host_decide::PodPolicy::observe_response(&pod.host_policy, 0).unwrap();
        })
        .await;
        assert!(!heard.head.granted, "{:?}", heard.head);
        assert!(heard.head.reason.starts_with("host policy refused:"));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(seen.lock().unwrap().is_empty());
        assert_eq!(pod.egress.counted(), 0);
    }

    #[tokio::test]
    async fn stream_host_gate_refuses_budget_taint_and_false_operation_labels() {
        for scenario in ["budget", "taint", "network"] {
            let (base, seen) = upstream().await;
            let mut pod = Pod::new(&base, 1 << 30, StreamLimits::DEFAULT);
            let mut req = open("model-api", "denied");
            let mut host_policy = pod.policy.clone();
            match scenario {
                "budget" => host_policy.budget.max_cost_usd = rust_decimal::Decimal::ZERO,
                "network" => {
                    host_policy.capabilities.web_fetch = portcullis::CapabilityLevel::Never;
                    req.operation = "ReadFiles".into();
                }
                "taint" => req.operation = "GitCommit".into(),
                _ => unreachable!(),
            }
            pod.host_policy = crate::host_decide::test_policy(host_policy);
            if scenario == "taint" {
                crate::host_decide::PodPolicy::observe_response(&pod.host_policy, 0).unwrap();
            }
            let heard = drive(&pod, &req, b"{}").await;
            assert!(!heard.head.granted, "{scenario}: {:?}", heard.head);
            assert!(
                heard.head.reason.starts_with("host policy refused:"),
                "{scenario}: {:?}",
                heard.head
            );
            assert!(seen.lock().unwrap().is_empty());
            assert_eq!(pod.egress.counted(), 0);
        }
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
        assert!(seen.lock().expect("log").is_empty());
        assert_eq!(pod.egress.counted(), 0);
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
