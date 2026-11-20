//! Asking the node: one `Decide` frame per request, over the socket the node
//! handed the proxy at spawn (ADR 0015 §2, §7).
//!
//! The frames are `nucleus-decision-protocol`'s, unchanged: the operation is
//! [`crate::summary::OPERATION`], the subject is the request's canonical
//! [`crate::summary::Summary`] text, and the digest is
//! [`crate::summary::digest`] of that text. The node recomputes the digest
//! from the subject it received and decides on the parsed summary, so what
//! the proxy claims is checked, never trusted (ADR 0007 C-2).
//!
//! # No answer is a denial (ADR 0014 §7)
//!
//! [`HostAnswer`] is a verdict or [`HostUnavailable`], as a type rather than a
//! `Result<bool>` (ADR 0007 A-1). Every way of not getting a verdict is its
//! own [`HostUnavailable`] arm: the deadline passing, the node closing the
//! socket, a frame that does not parse, an answer to a different question,
//! and the proxy being too busy to ask in time. Each refuses the request.
//!
//! # A late answer is dropped, not a broken peer (`DecisionChannel.lean`)
//!
//! A request whose deadline passes is refused, and its number is *owed*: the
//! node's answer, when it comes, is dropped by number and never read as the
//! answer to another request. The channel stays in use. Found 2026-11-19 (ADR
//! 0017 local rehearsal): the first version poisoned the channel on any missed
//! deadline, assuming a late answer meant a broken peer, so one answer 0.2 s
//! late left a pod whose links and egress never carried anything again.
//!
//! What still poisons is evidence of a broken peer: an answer whose number is
//! neither the outstanding request's nor owed, a frame that does not parse or is
//! not a verdict, the node closing the socket, a request frame cut short by the
//! deadline (the node saw a partial frame), and more than [`OWED_CAP`] owed
//! answers (the node is not answering at all). Both decisions go through the
//! extracted `nucleus_ifc_kernel::extracted::decision` functions.
//!
//! Reads are cancel-safe: bytes go into a buffer kept across requests, so a
//! deadline that fires mid-frame loses nothing and the next request resumes
//! the frame where it stopped.

use std::time::Duration;

use nucleus_decision_protocol::{
    ArgsDigest, DenyReason, GuestFrame, HostFrame, LEN_PREFIX, Seq, Subject, Verdict, body_len,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::summary::OPERATION;

/// How long a request waits for the node's verdict (ADR 0014 §7, ADR 0015
/// §10's hard decision deadline). Past it the request is refused.
pub const DECISION_DEADLINE: Duration = Duration::from_secs(2);

/// What the node answered, or that it did not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostAnswer {
    /// The node decided.
    Verdict(Decided),
    /// The node did not decide. Enforced as a refusal.
    Unreachable(HostUnavailable),
}

/// A verdict, without the id that carried it. The node redeems the decision
/// id it minted before it answers (ADR 0015 §2, C-4), so the copy that
/// arrives here authorizes nothing and is dropped on arrival.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decided {
    Allowed,
    Denied(DenyReason),
    ApprovalRequired,
}

/// Why there is no verdict. Each has its own refusal code (ADR 0007 I-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostUnavailable {
    /// [`DECISION_DEADLINE`] passed with no answer.
    Timeout,
    /// Other requests held the channel until the deadline passed.
    Overloaded,
    /// The node closed the channel.
    Closed,
    /// Reading or writing the channel failed.
    Io,
    /// The node's frame did not parse, or ours could not be encoded.
    Protocol,
    /// The node answered with a frame that is not a verdict.
    UnexpectedFrame,
    /// The node answered a different frame number.
    OutOfSequence,
    /// An earlier exchange failed, so this channel is no longer trusted.
    Poisoned,
    /// The channel has carried every frame number it has.
    Exhausted,
}

impl HostUnavailable {
    /// The refusal code.
    pub const fn code(self) -> &'static str {
        match self {
            HostUnavailable::Timeout => "host_unavailable_timeout",
            HostUnavailable::Overloaded => "host_unavailable_overloaded",
            HostUnavailable::Closed => "host_unavailable_closed",
            HostUnavailable::Io => "host_unavailable_io",
            HostUnavailable::Protocol => "host_unavailable_protocol",
            HostUnavailable::UnexpectedFrame => "host_unavailable_unexpected_frame",
            HostUnavailable::OutOfSequence => "host_unavailable_out_of_sequence",
            HostUnavailable::Poisoned => "host_unavailable_poisoned",
            HostUnavailable::Exhausted => "host_unavailable_exhausted",
        }
    }
}

/// How many owed answers a channel tolerates before the node counts as not
/// answering at all (`DecisionChannel.cap`).
pub const OWED_CAP: u32 = 64;

/// The proxy's end of its decision channel.
#[derive(Debug)]
pub struct DecisionClient<S> {
    stream: S,
    /// The number the node expects next; `None` once every number is used.
    next: Option<Seq>,
    poisoned: bool,
    /// Numbers whose request timed out: their answers are owed and dropped.
    owed: Vec<Seq>,
    /// Bytes read but not yet a whole frame, kept across requests so a
    /// deadline that fires mid-read loses nothing.
    buf: Vec<u8>,
    /// Whether the current request's frame reached the node whole.
    frame_written: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> DecisionClient<S> {
    /// A client on a fresh channel.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            next: Some(Seq::FIRST),
            poisoned: false,
            owed: Vec::new(),
            buf: Vec::new(),
            frame_written: false,
        }
    }

    /// How many answers the node owes for requests that timed out.
    #[must_use]
    pub fn owed(&self) -> usize {
        self.owed.len()
    }

    /// Ask the node about one request, waiting at most `deadline`.
    pub async fn decide(
        &mut self,
        subject: Subject,
        digest: ArgsDigest,
        deadline: Duration,
    ) -> HostAnswer {
        use nucleus_ifc_kernel::extracted::decision::{OnDeadline, on_deadline};
        if self.poisoned {
            return HostAnswer::Unreachable(HostUnavailable::Poisoned);
        }
        let Some(seq) = self.next else {
            return HostAnswer::Unreachable(HostUnavailable::Exhausted);
        };
        let frame = GuestFrame::Decide {
            seq,
            op: OPERATION,
            subject,
            args_digest: digest,
        };
        self.frame_written = false;
        match tokio::time::timeout(deadline, self.exchange(&frame, seq)).await {
            Ok(HostAnswer::Verdict(v)) => HostAnswer::Verdict(v),
            Ok(HostAnswer::Unreachable(why)) => {
                self.poisoned = true;
                HostAnswer::Unreachable(why)
            }
            Err(_) => {
                let owed_after =
                    u32::try_from(self.owed.len().saturating_add(1)).unwrap_or(u32::MAX);
                match on_deadline(self.frame_written, owed_after, OWED_CAP) {
                    OnDeadline::RefuseAndOwe => self.owed.push(seq),
                    OnDeadline::RefuseAndPoison => self.poisoned = true,
                }
                HostAnswer::Unreachable(HostUnavailable::Timeout)
            }
        }
    }

    async fn exchange(&mut self, frame: &GuestFrame, seq: Seq) -> HostAnswer {
        use HostUnavailable as U;
        use nucleus_ifc_kernel::extracted::decision::{Disposition, disposition};
        let unreachable = HostAnswer::Unreachable;
        let Ok(bytes) = frame.encode() else {
            return unreachable(U::Protocol);
        };
        if self.stream.write_all(&bytes).await.is_err() || self.stream.flush().await.is_err() {
            return unreachable(U::Io);
        }
        // The node has this number now: the next request takes the next one,
        // whatever happens to this one.
        self.frame_written = true;
        self.next = seq.next();
        loop {
            let reply = match self.read_frame().await {
                Ok(reply) => reply,
                Err(why) => return unreachable(why),
            };
            let (got, verdict) = match reply {
                HostFrame::Verdict { seq: got, verdict } => (got, verdict),
                HostFrame::Observed { seq: _ }
                | HostFrame::Compared {
                    seq: _,
                    agreement: _,
                } => return unreachable(U::UnexpectedFrame),
            };
            match disposition(got == seq, self.owed.contains(&got)) {
                Disposition::Apply => {
                    return HostAnswer::Verdict(match verdict {
                        Verdict::Allowed { decision_id } => {
                            // Already redeemed by the node; see `Decided`.
                            drop(decision_id);
                            Decided::Allowed
                        }
                        Verdict::Denied { reason } => Decided::Denied(reason),
                        Verdict::ApprovalRequired { approval_id } => {
                            drop(approval_id);
                            Decided::ApprovalRequired
                        }
                    });
                }
                Disposition::DropLate => {
                    // A timed-out request's answer: dropped by number, never
                    // read as this request's (`late_answer_never_admits`).
                    self.owed.retain(|s| *s != got);
                }
                Disposition::Poison => return unreachable(U::OutOfSequence),
            }
        }
    }

    /// One whole frame from the node. Cancel-safe: `read` either returns
    /// bytes, which go into `buf`, or is dropped having read nothing.
    async fn read_frame(&mut self) -> Result<HostFrame, HostUnavailable> {
        use HostUnavailable as U;
        loop {
            if let Some(head) = self.buf.get(..LEN_PREFIX) {
                let prefix: [u8; LEN_PREFIX] = head.try_into().map_err(|_| U::Protocol)?;
                let len = body_len(prefix).map_err(|_| U::Protocol)?;
                let end = LEN_PREFIX.checked_add(len).ok_or(U::Protocol)?;
                if let Some(body) = self.buf.get(LEN_PREFIX..end) {
                    let reply = HostFrame::decode_body(body).map_err(|_| U::Protocol)?;
                    self.buf.drain(..end);
                    return Ok(reply);
                }
            }
            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk).await {
                Ok(0) => return Err(U::Closed),
                Ok(n) => self
                    .buf
                    .extend_from_slice(chunk.get(..n).unwrap_or_default()),
                Err(_) => return Err(U::Io),
            }
        }
    }
}

/// One decision channel shared by every guest connection of the pod.
///
/// Requests ask one at a time. Waiting for the channel counts against the
/// same deadline as the answer: a request that cannot even ask in time is
/// [`HostUnavailable::Overloaded`], refused like any other non-answer.
#[derive(Debug)]
pub struct SharedDecider<S> {
    client: Mutex<DecisionClient<S>>,
    deadline: Duration,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> SharedDecider<S> {
    /// Share `stream`, answering within `deadline`.
    pub fn new(stream: S, deadline: Duration) -> Self {
        Self {
            client: Mutex::new(DecisionClient::new(stream)),
            deadline,
        }
    }

    /// Ask, within the deadline.
    pub async fn decide(&self, subject: Subject, digest: ArgsDigest) -> HostAnswer {
        let started = tokio::time::Instant::now();
        let Ok(mut client) = tokio::time::timeout(self.deadline, self.client.lock()).await else {
            return HostAnswer::Unreachable(HostUnavailable::Overloaded);
        };
        let left = self.deadline.saturating_sub(started.elapsed());
        client.decide(subject, digest, left).await
    }
}
