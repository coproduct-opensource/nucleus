//! The guest's half of the host's shadow decision service (#2702, P8).
//!
//! Every decision this proxy's kernel takes is ALSO put to the host, over the
//! decision channel ([`nucleus_decision_protocol::DECISION_VSOCK_PORT`]). The
//! proxy still enforces its OWN decision — this is shadow mode — and tells the
//! host what that decision was, so the host can compare and record each
//! disagreement. The host decides agreement ([`Agreement::of`] runs there) and
//! says so in its `Compared` reply; this side only counts what it was told.
//!
//! # Never in the way
//!
//! A decision point hands its question to [`HostDecide::submit`], which is
//! synchronous and never waits: it puts the question on a bounded queue and
//! returns. One worker task drains the queue and talks to the host. So a slow,
//! dead or hostile host costs a decision nothing; it shows up as
//! [`HostUnavailable`] in the tally instead. The queue is filled while the
//! caller still holds its kernel lock, so each kernel session's questions reach
//! the host in the order that kernel decided them — which is what makes the
//! host's kernel, fed the same sequence, comparable.
//!
//! # One channel per kernel session
//!
//! The HTTP transport's kernel and each MCP server's kernel are separate
//! sessions with separate exposure. Each gets its own channel (keyed by
//! `Kernel::session_id`), so the host keeps one kernel per guest kernel rather
//! than one fed by two interleaved histories.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use nucleus::portcullis::Operation;
use nucleus::portcullis::flow_graph::FlowGraph;
use nucleus::portcullis::kernel::{Kernel, Verdict as KernelVerdict};
use nucleus_decision_protocol::kernel::{args_digest, outcome_of, taint_report};
use nucleus_decision_protocol::{
    Agreement, GuestFrame, HostFrame, LEN_PREFIX, LabelRaise, Outcome, Seq, Subject, Verdict,
    body_len,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

/// Questions waiting for the worker. Past this, a decision's shadow is dropped
/// and counted as [`HostUnavailable::Backlog`] rather than queued without bound.
const QUEUE: usize = 1024;

/// How long the worker waits to connect, and for each reply.
const DEADLINE: Duration = Duration::from_secs(2);

/// The most kernel sessions with an open channel at once.
const MAX_SESSIONS: usize = 16;

/// Why a decision's shadow never reached a comparison. Typed, so a host that
/// cannot be dialled reads differently from one that answered nonsense.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostUnavailable {
    /// The channel could not be opened.
    Connect,
    /// The host did not answer within [`DEADLINE`].
    Timeout,
    /// The channel failed mid-exchange.
    Io,
    /// The host answered with a frame that is not the answer to the question.
    Protocol,
    /// The worker's queue was full; the question was dropped.
    Backlog,
    /// More kernel sessions than [`MAX_SESSIONS`] asked at once.
    TooManySessions,
    /// The worker is gone.
    Stopped,
}

/// What one shadowed decision came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shadowed {
    /// The host said it agreed.
    Agreed,
    /// The host said it disagreed, and has recorded both outcomes.
    Disagreed,
    /// The host never compared it.
    Unavailable(HostUnavailable),
}

/// This proxy's shadow counters.
#[derive(Debug, Default)]
pub(crate) struct GuestTally {
    agree: AtomicU64,
    disagree: AtomicU64,
    unavailable: AtomicU64,
    last_unavailable: std::sync::Mutex<Option<HostUnavailable>>,
}

/// A point-in-time read of a [`GuestTally`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GuestSnapshot {
    pub agree: u64,
    pub disagree: u64,
    pub unavailable: u64,
    pub last_unavailable: Option<HostUnavailable>,
}

impl GuestTally {
    fn count(&self, s: Shadowed) {
        match s {
            Shadowed::Agreed => {
                self.agree.fetch_add(1, Ordering::SeqCst);
            }
            Shadowed::Disagreed => {
                self.disagree.fetch_add(1, Ordering::SeqCst);
            }
            Shadowed::Unavailable(why) => {
                self.unavailable.fetch_add(1, Ordering::SeqCst);
                if let Ok(mut last) = self.last_unavailable.lock() {
                    *last = Some(why);
                }
            }
        }
    }

    pub(crate) fn snapshot(&self) -> GuestSnapshot {
        GuestSnapshot {
            agree: self.agree.load(Ordering::SeqCst),
            disagree: self.disagree.load(Ordering::SeqCst),
            unavailable: self.unavailable.load(Ordering::SeqCst),
            last_unavailable: self.last_unavailable.lock().ok().and_then(|g| *g),
        }
    }
}

/// A byte stream to the host.
pub(crate) trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

type Dialled = Pin<Box<dyn Future<Output = std::io::Result<Box<dyn Duplex>>> + Send>>;

/// How the worker opens a channel. The vsock dialer in production; a test's
/// in-memory host otherwise.
pub(crate) type Dialer = Arc<dyn Fn() -> Dialled + Send + Sync>;

/// One decision, as the worker will put it to the host.
#[derive(Debug)]
pub(crate) struct Question {
    session: Uuid,
    op: Operation,
    subject: String,
    local: Outcome,
    taint: LabelRaise,
}

pub(crate) enum Work {
    Ask(Question),
    /// Answered once everything queued before it has been handled.
    #[cfg(test)]
    Flush(tokio::sync::oneshot::Sender<()>),
}

/// Whether this proxy shadows its decisions to the host, and if so, the queue.
#[derive(Debug)]
pub(crate) enum HostDecide {
    /// No host decision channel exists for this proxy — it is not running in a
    /// Firecracker guest. Reported as `off` in health, never as zero
    /// disagreements: not having looked is not having agreed.
    Off,
    On {
        queue: tokio::sync::mpsc::Sender<Work>,
        tally: Arc<GuestTally>,
    },
}

impl std::fmt::Debug for Work {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Work::Ask(q) => q.fmt(f),
            #[cfg(test)]
            Work::Flush(_) => f.write_str("Flush"),
        }
    }
}

impl HostDecide {
    /// The shadow client for this proxy: on, dialling the host over vsock,
    /// when the proxy serves over vsock (it is in a Firecracker guest); off
    /// otherwise.
    pub(crate) fn for_transport(vsock: bool) -> Self {
        match vsock_dialer(vsock) {
            Some(dial) => Self::start(dial),
            None => HostDecide::Off,
        }
    }

    /// Start the worker. Needs a Tokio runtime.
    pub(crate) fn start(dial: Dialer) -> Self {
        let (queue, rx) = tokio::sync::mpsc::channel(QUEUE);
        let tally = Arc::new(GuestTally::default());
        tokio::spawn(worker(rx, dial, Arc::clone(&tally)));
        HostDecide::On { queue, tally }
    }

    /// Put one decision to the host as well. Never waits, never fails the
    /// caller: the caller has already decided and will enforce its own answer.
    ///
    /// Takes what the decision point holds — its kernel (for the session), its
    /// graph (for the taint report) and the verdict — so a decision point
    /// cannot report a verdict without the state it was decided against.
    pub(crate) fn submit(
        &self,
        kernel: &Kernel,
        graph: &FlowGraph,
        op: Operation,
        subject: &str,
        verdict: &KernelVerdict,
    ) {
        let HostDecide::On { queue, tally } = self else {
            return;
        };
        let q = Question {
            session: kernel.session_id(),
            op,
            subject: subject.to_string(),
            local: outcome_of(verdict),
            taint: taint_report(graph),
        };
        match queue.try_send(Work::Ask(q)) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                tally.count(Shadowed::Unavailable(HostUnavailable::Backlog))
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                tally.count(Shadowed::Unavailable(HostUnavailable::Stopped))
            }
        }
    }

    /// The counters, or `None` when shadowing is off.
    pub(crate) fn snapshot(&self) -> Option<GuestSnapshot> {
        match self {
            HostDecide::Off => None,
            HostDecide::On { tally, .. } => Some(tally.snapshot()),
        }
    }

    /// For `/v1/health`: counts only, never operations or subjects — the
    /// endpoint is reachable from inside the sandbox.
    pub(crate) fn health_json(&self) -> serde_json::Value {
        match self.snapshot() {
            None => serde_json::json!({ "mode": "off" }),
            Some(s) => serde_json::json!({
                "mode": "shadow",
                "agree": s.agree,
                "disagree": s.disagree,
                "unavailable": s.unavailable,
                "last_unavailable": s.last_unavailable.map(|u| format!("{u:?}")),
            }),
        }
    }

    /// Wait until every question queued so far has been handled.
    #[cfg(test)]
    pub(crate) async fn flush(&self) {
        if let HostDecide::On { queue, .. } = self {
            let (tx, rx) = tokio::sync::oneshot::channel();
            if queue.send(Work::Flush(tx)).await.is_ok() {
                let _ = rx.await;
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn vsock_dialer(vsock: bool) -> Option<Dialer> {
    /// The host's CID. Always 2 under Firecracker.
    const VMADDR_CID_HOST: u32 = 2;
    if !vsock {
        return None;
    }
    Some(Arc::new(|| {
        Box::pin(async {
            let s = tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(
                VMADDR_CID_HOST,
                nucleus_decision_protocol::DECISION_VSOCK_PORT,
            ))
            .await?;
            Ok(Box::new(s) as Box<dyn Duplex>)
        })
    }))
}

#[cfg(not(target_os = "linux"))]
fn vsock_dialer(_vsock: bool) -> Option<Dialer> {
    None
}

/// One open channel: the stream, the next frame number, and the last taint
/// report the host acknowledged.
struct Channel {
    io: Box<dyn Duplex>,
    next: Seq,
    reported: Option<LabelRaise>,
}

impl Channel {
    fn seq(&mut self) -> Result<Seq, HostUnavailable> {
        let s = self.next;
        self.next = s.next().ok_or(HostUnavailable::Protocol)?;
        Ok(s)
    }

    async fn ask(&mut self, frame: GuestFrame) -> Result<HostFrame, HostUnavailable> {
        let bytes = frame.encode().map_err(|_| HostUnavailable::Protocol)?;
        let exchange = async {
            self.io
                .write_all(&bytes)
                .await
                .map_err(|_| HostUnavailable::Io)?;
            let mut prefix = [0u8; LEN_PREFIX];
            self.io
                .read_exact(&mut prefix)
                .await
                .map_err(|_| HostUnavailable::Io)?;
            let mut body = vec![0u8; body_len(prefix).map_err(|_| HostUnavailable::Protocol)?];
            self.io
                .read_exact(&mut body)
                .await
                .map_err(|_| HostUnavailable::Io)?;
            HostFrame::decode_body(&body).map_err(|_| HostUnavailable::Protocol)
        };
        tokio::time::timeout(DEADLINE, exchange)
            .await
            .map_err(|_| HostUnavailable::Timeout)?
    }

    /// Observe (if the taint moved), Decide, Shadow.
    async fn shadow(&mut self, q: Question) -> Result<Agreement, HostUnavailable> {
        let Question {
            session: _,
            op,
            subject,
            local,
            taint,
        } = q;
        if self.reported != Some(taint) {
            let seq = self.seq()?;
            match self
                .ask(GuestFrame::Observe {
                    seq,
                    label_raise: taint,
                })
                .await?
            {
                HostFrame::Observed { seq: s } if s == seq => self.reported = Some(taint),
                _ => return Err(HostUnavailable::Protocol),
            }
        }
        // A subject past the wire's bound is cut to it; the digest binds what
        // was sent, and a shadow of a truncated subject is still a shadow of
        // the same operation.
        let subject = Subject::new(truncate(&subject)).map_err(|_| HostUnavailable::Protocol)?;
        let decided = self.seq()?;
        let digest = args_digest(op, &subject);
        let verdict = match self
            .ask(GuestFrame::Decide {
                seq: decided,
                op,
                subject,
                args_digest: digest,
            })
            .await?
        {
            HostFrame::Verdict { seq, verdict } if seq == decided => verdict,
            _ => return Err(HostUnavailable::Protocol),
        };
        // Shadow mode: the host's ids are not acted on. Dropped on purpose; the
        // host retires them when it reads the report below.
        match verdict {
            Verdict::Allowed { decision_id } => drop(decision_id),
            Verdict::ApprovalRequired { approval_id } => drop(approval_id),
            Verdict::Denied { reason: _ } => {}
        }
        let seq = self.seq()?;
        match self
            .ask(GuestFrame::Shadow {
                seq,
                decided,
                local,
            })
            .await?
        {
            HostFrame::Compared { seq: s, agreement } if s == seq => Ok(agreement),
            _ => Err(HostUnavailable::Protocol),
        }
    }
}

/// The longest prefix of `s` that fits the wire's subject bound, on a char
/// boundary.
fn truncate(s: &str) -> &str {
    let max = nucleus_decision_protocol::MAX_SUBJECT_LEN;
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

async fn worker(mut rx: tokio::sync::mpsc::Receiver<Work>, dial: Dialer, tally: Arc<GuestTally>) {
    let mut channels: HashMap<Uuid, Channel> = HashMap::new();
    while let Some(work) = rx.recv().await {
        match work {
            Work::Ask(q) => tally.count(put(&mut channels, &dial, q).await),
            #[cfg(test)]
            Work::Flush(done) => {
                let _ = done.send(());
            }
        }
    }
}

/// Put one question to the host on its session's channel, opening the channel
/// if there is none.
async fn put(channels: &mut HashMap<Uuid, Channel>, dial: &Dialer, q: Question) -> Shadowed {
    let session = q.session;
    let opened = match channels.remove(&session) {
        Some(ch) => Ok(ch),
        None if channels.len() >= MAX_SESSIONS => Err(HostUnavailable::TooManySessions),
        None => match tokio::time::timeout(DEADLINE, dial()).await {
            Ok(Ok(io)) => Ok(Channel {
                io,
                next: Seq::FIRST,
                reported: None,
            }),
            Ok(Err(_)) => Err(HostUnavailable::Connect),
            Err(_) => Err(HostUnavailable::Timeout),
        },
    };
    let shadowed = match opened {
        Err(why) => Shadowed::Unavailable(why),
        Ok(mut ch) => match ch.shadow(q).await {
            Ok(agreement) => {
                channels.insert(session, ch);
                match agreement {
                    Agreement::Agree => Shadowed::Agreed,
                    Agreement::Disagree => Shadowed::Disagreed,
                }
            }
            // The channel is dropped: its numbering is no longer known to
            // match the host's, and the next question reopens it.
            Err(why) => Shadowed::Unavailable(why),
        },
    };
    if let Shadowed::Unavailable(why) = shadowed {
        tracing::debug!(
            ?why,
            "host-decide shadow: the host did not compare this decision"
        );
    }
    shadowed
}

#[cfg(test)]
#[path = "host_decide_tests.rs"]
mod tests;
