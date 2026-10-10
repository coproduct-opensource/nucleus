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
//! and the proxy being too busy to ask in time. Each refuses the request, and
//! after any of them the channel is poisoned: a reply that arrives late could
//! otherwise be read as the answer to the next question.

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

/// The proxy's end of its decision channel.
#[derive(Debug)]
pub struct DecisionClient<S> {
    stream: S,
    /// The number the node expects next; `None` once every number is used.
    next: Option<Seq>,
    poisoned: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> DecisionClient<S> {
    /// A client on a fresh channel.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            next: Some(Seq::FIRST),
            poisoned: false,
        }
    }

    /// Ask the node about one request, waiting at most `deadline`.
    pub async fn decide(
        &mut self,
        subject: Subject,
        digest: ArgsDigest,
        deadline: Duration,
    ) -> HostAnswer {
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
        let answer = match tokio::time::timeout(deadline, self.exchange(&frame, seq)).await {
            Ok(answer) => answer,
            Err(_) => HostAnswer::Unreachable(HostUnavailable::Timeout),
        };
        match answer {
            HostAnswer::Verdict(_) => self.next = seq.next(),
            HostAnswer::Unreachable(_) => self.poisoned = true,
        }
        answer
    }

    async fn exchange(&mut self, frame: &GuestFrame, seq: Seq) -> HostAnswer {
        use HostUnavailable as U;
        let unreachable = HostAnswer::Unreachable;
        let Ok(bytes) = frame.encode() else {
            return unreachable(U::Protocol);
        };
        if self.stream.write_all(&bytes).await.is_err() || self.stream.flush().await.is_err() {
            return unreachable(U::Io);
        }
        let mut prefix = [0u8; LEN_PREFIX];
        if let Err(e) = self.stream.read_exact(&mut prefix).await {
            return unreachable(match e.kind() {
                std::io::ErrorKind::UnexpectedEof => U::Closed,
                _ => U::Io,
            });
        }
        let Ok(len) = body_len(prefix) else {
            return unreachable(U::Protocol);
        };
        let mut body = vec![0u8; len];
        if let Err(e) = self.stream.read_exact(&mut body).await {
            return unreachable(match e.kind() {
                std::io::ErrorKind::UnexpectedEof => U::Closed,
                _ => U::Io,
            });
        }
        let Ok(reply) = HostFrame::decode_body(&body) else {
            return unreachable(U::Protocol);
        };
        match reply {
            HostFrame::Verdict { seq: got, verdict } if got == seq => {
                HostAnswer::Verdict(match verdict {
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
                })
            }
            HostFrame::Verdict { seq: _, verdict: _ } => unreachable(U::OutOfSequence),
            HostFrame::Observed { seq: _ }
            | HostFrame::Compared {
                seq: _,
                agreement: _,
            } => unreachable(U::UnexpectedFrame),
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
