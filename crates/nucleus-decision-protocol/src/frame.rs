//! The frames and the values they carry.

use nucleus_ifc_kernel::{IFCLabel, Operation};

/// The host's count of frames on one decision channel.
///
/// The host assigns these: [`crate::host::SeqGate`] admits only the next number
/// and refuses anything else. A guest that sends a frame is echoing the number
/// the host expects next, starting from [`Seq::FIRST`]; a reply carries the
/// number of the frame it answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Seq(u64);

impl Seq {
    /// The number of the first frame on a fresh channel.
    pub const FIRST: Seq = Seq(0);

    /// A sequence number as read off the wire or chosen by the guest.
    ///
    /// Public on purpose: a `Seq` is a claim, not an authority. The host's
    /// [`crate::host::SeqGate`] is what decides whether it is the right one.
    pub const fn new(n: u64) -> Self {
        Self(n)
    }

    /// The raw number.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The number after this one, or `None` at `u64::MAX` — a channel that has
    /// carried 2^64 frames ends rather than wrapping onto a number it has used.
    pub const fn next(self) -> Option<Seq> {
        match self.0.checked_add(1) {
            Some(n) => Some(Seq(n)),
            None => None,
        }
    }
}

/// A host-minted, single-use right to perform one decided operation.
///
/// # What makes it single-use
///
/// * **Private constructor** (ADR 0007 C-1). It is minted by
///   [`crate::host::DecisionLedger`] — the thing that decides — and by the
///   decoder, which turns host bytes back into the value the host sent.
/// * **`!Clone`, `!Copy`, `#[must_use]`** (C-5): holding one does not let you
///   hold two.
/// * **Consumed by value** (C-4): [`crate::host::DecisionLedger::consume`]
///   takes `self`, not `&self`. `DischargedBundle` in `f7f9719b` had every
///   affine signal Rust offers and was still replayable because three
///   signatures borrowed it; there is no borrowing consumer here.
///
/// # What the type cannot do, and what does
///
/// A decision id that crossed the wire is bytes, and bytes decode as often as
/// anyone likes — a guest replaying a frame holds two equal `DecisionId`s. The
/// type therefore cannot be the replay defence on its own; the host ledger is.
/// It forgets an id the moment it is consumed, so the second presentation is
/// [`crate::host::LedgerError::Retired`]. The type's job is the in-process
/// half: no host code path can spend one value twice.
///
/// # Why it carries its ledger's epoch
///
/// Every ledger numbers from zero. Without the epoch, decision 0 from a
/// channel that has since closed is decision 0 on the channel that replaced it
/// — a replay across a reconnect that no per-ledger bookkeeping can see, the
/// same hole `EgressHold` had before it carried its ledger's epoch (#3112). The
/// epoch names the ledger that decided, and
/// [`crate::host::DecisionLedger::consume`] refuses one it did not issue
/// ([`crate::host::LedgerError::ForeignEpoch`]) before the number is looked at.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a DecisionId is a one-shot right; drop it only on purpose"]
pub struct DecisionId {
    epoch: u64,
    number: u64,
}

impl DecisionId {
    pub(crate) const fn mint(epoch: u64, number: u64) -> Self {
        Self { epoch, number }
    }

    /// The epoch of the ledger that issued it.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The number, for a receipt or a log line. Reading it mints nothing.
    pub const fn number(&self) -> u64 {
        self.number
    }
}

/// A host-minted handle on one pending approval, bound to exactly one
/// [`DecisionId`] the host reserved when it asked for the approval.
///
/// Same discipline as [`DecisionId`], epoch included: private constructor,
/// `!Clone`, `!Copy`, and redeemed by value
/// ([`crate::host::DecisionLedger::redeem`]). Redeeming a granted approval
/// yields its one reserved decision id and retires the approval, so one human
/// approval authorizes one operation.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "an ApprovalId is redeemable once; drop it only on purpose"]
pub struct ApprovalId {
    epoch: u64,
    number: u64,
}

impl ApprovalId {
    pub(crate) const fn mint(epoch: u64, number: u64) -> Self {
        Self { epoch, number }
    }

    /// The epoch of the ledger that issued it.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The number shown to the approver. Reading it mints nothing.
    pub const fn number(&self) -> u64 {
        self.number
    }
}

/// The longest subject, in bytes, a [`GuestFrame::Decide`] may carry.
///
/// A path, a URL, a command line. Long enough for any of them that a policy
/// can usefully reason about; short enough that one frame is a bounded
/// allocation on the host.
///
/// The subject's length rides the wire as a `u16`; the encoder converts with
/// `u16::try_from`, and `max_subject_encodes` in the tests pins that this bound
/// fits it.
pub const MAX_SUBJECT_LEN: usize = 4096;

/// What an operation is applied to — a path, a URL, a command line.
///
/// UTF-8 and at most [`MAX_SUBJECT_LEN`] bytes, by construction: there is no
/// way to hold a `Subject` that the encoder could not write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject(String);

/// Why a string was refused as a [`Subject`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubjectError {
    /// Longer than [`MAX_SUBJECT_LEN`] bytes.
    TooLong { len: usize },
}

impl std::fmt::Display for SubjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubjectError::TooLong { len } => {
                write!(f, "subject is {len} bytes (max {MAX_SUBJECT_LEN})")
            }
        }
    }
}

impl std::error::Error for SubjectError {}

impl Subject {
    /// A subject, or a refusal if it is longer than [`MAX_SUBJECT_LEN`].
    pub fn new(text: impl Into<String>) -> Result<Self, SubjectError> {
        let text = text.into();
        if text.len() > MAX_SUBJECT_LEN {
            return Err(SubjectError::TooLong { len: text.len() });
        }
        Ok(Self(text))
    }

    /// The subject text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A digest of an operation's full arguments, so a decision is bound to the
/// exact call it was taken for and not merely to its operation and subject.
///
/// 32 bytes. The digest function is the canonical-args encoder's choice, made
/// where the arguments are canonicalised (P8); this protocol only carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArgsDigest([u8; ArgsDigest::LEN]);

impl ArgsDigest {
    /// The digest's width in bytes.
    pub const LEN: usize = 32;

    /// Wrap a digest.
    pub const fn new(bytes: [u8; Self::LEN]) -> Self {
        Self(bytes)
    }

    /// The digest bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::LEN] {
        &self.0
    }
}

/// A taint report from the guest that can only ever raise the host's label.
///
/// Owner decision D2: taint is host-computed, and a guest report may only
/// raise it. This type is how "only raise" is a property of the protocol
/// rather than of the host's care.
///
/// It carries an [`IFCLabel`], and its one consumer, [`LabelRaise::raise`], is
/// the lattice join of that label with the label the host holds. A join is an
/// upper bound of both operands, so the result is at least as restrictive as
/// the host's label in every dimension — whatever the guest wrote. There is no
/// accessor that hands the carried label back for any other use, so there is no
/// path by which a report replaces, or is compared against, the host's label.
///
/// A raise that names a *less* restrictive label than the host holds is not an
/// error and not a lowering: the join absorbs it and nothing changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LabelRaise(IFCLabel);

impl LabelRaise {
    /// A report that the guest has seen data labelled `observed`.
    pub const fn new(observed: IFCLabel) -> Self {
        Self(observed)
    }

    /// The host's label after this report: `current ⊔ observed`.
    ///
    /// Never less restrictive than `current` in any dimension.
    #[must_use = "the raised label is the new taint; discarding it drops the report"]
    pub fn raise(self, current: IFCLabel) -> IFCLabel {
        current.join(self.0)
    }

    /// The carried label, for the encoder only.
    pub(crate) const fn wire_label(&self) -> IFCLabel {
        self.0
    }
}

/// Why the host refused an operation.
///
/// A closed vocabulary: the decoder refuses a reason it does not know, and a
/// new reason is a new variant that breaks every exhaustive match until it is
/// encoded (ADR 0007 E-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DenyReason {
    /// The pod's capability lattice does not grant this operation.
    NotGranted,
    /// The session's taint forbids this flow.
    FlowRefused,
    /// The pod's budget does not cover this operation.
    BudgetExhausted,
    /// A human refused the approval this operation was waiting on.
    ApprovalRefused,
    /// The approval this operation was waiting on lapsed before anyone decided.
    ApprovalExpired,
    /// The approval presented was never issued on this channel, or was already
    /// redeemed.
    ApprovalUnknown,
}

impl DenyReason {
    /// Every reason. The decoder searches this list, so a reason missing from
    /// it is refused on the wire rather than misread (fail-closed); the
    /// `every_enum_value_round_trips` test catches the omission.
    pub const ALL: [DenyReason; 6] = [
        DenyReason::NotGranted,
        DenyReason::FlowRefused,
        DenyReason::BudgetExhausted,
        DenyReason::ApprovalRefused,
        DenyReason::ApprovalExpired,
        DenyReason::ApprovalUnknown,
    ];
}

/// The host's answer to a [`GuestFrame::Decide`] or [`GuestFrame::Redeem`].
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Permitted. The id is the one-shot right to perform it.
    Allowed { decision_id: DecisionId },
    /// Refused, with the reason.
    Denied { reason: DenyReason },
    /// Permitted only if a human approves. Redeem the id with
    /// [`GuestFrame::Redeem`] once they have.
    ApprovalRequired { approval_id: ApprovalId },
}

impl Verdict {
    /// What was decided, without the id that carries the right to act on it.
    pub const fn outcome(&self) -> Outcome {
        match self {
            Verdict::Allowed { decision_id: _ } => Outcome::Allowed,
            Verdict::Denied { reason } => Outcome::Denied { reason: *reason },
            Verdict::ApprovalRequired { approval_id: _ } => Outcome::ApprovalRequired,
        }
    }
}

/// A decision's class: what a [`Verdict`] says, with no id attached.
///
/// The unit of comparison in shadow mode (#2702, P8). The guest reports the
/// outcome its own kernel reached in a [`GuestFrame::Shadow`]; the host compares
/// it with the outcome of the [`Verdict`] it sent. An outcome carries no
/// decision or approval id, so a report of one grants nothing and anyone can
/// write it: it is a claim the host records, never a right it honours.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// Permitted.
    Allowed,
    /// Refused, for this reason.
    Denied { reason: DenyReason },
    /// Deferred to a human.
    ApprovalRequired,
}

/// Whether the host's verdict and the guest's own decision were the same
/// [`Outcome`].
///
/// Decided by the host, once ([`Agreement::of`]), and told to the guest in
/// [`HostFrame::Compared`], so the host's tally and the guest's cannot count
/// the same exchange differently (ADR 0007 G-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Agreement {
    /// The same outcome.
    Agree,
    /// Different outcomes. The host keeps a record naming both.
    Disagree,
}

impl Agreement {
    /// Every value, for the decoder's search (as [`DenyReason::ALL`]).
    pub const ALL: [Agreement; 2] = [Agreement::Agree, Agreement::Disagree];

    /// The comparison. The one place agreement is decided.
    pub fn of(host: Outcome, guest: Outcome) -> Self {
        if host == guest {
            Agreement::Agree
        } else {
            Agreement::Disagree
        }
    }
}

/// A frame the guest sends.
#[derive(Debug, PartialEq, Eq)]
pub enum GuestFrame {
    /// May I perform `op` on `subject`, with arguments hashing to `args_digest`?
    Decide {
        seq: Seq,
        op: Operation,
        subject: Subject,
        args_digest: ArgsDigest,
    },
    /// I have observed data carrying this label. Raise-only by construction.
    Observe { seq: Seq, label_raise: LabelRaise },
    /// Redeem the approval I was told to wait for. Consumes the guest's handle.
    Redeem { seq: Seq, approval_id: ApprovalId },
    /// SHADOW MODE ONLY (P8): my own kernel decided the `Decide` numbered
    /// `decided` as `local`. The host compares that with its verdict and retires
    /// the id it issued for it. Goes when the guest's kernel does (owner
    /// decision D6).
    Shadow {
        seq: Seq,
        decided: Seq,
        local: Outcome,
    },
}

/// A frame the host sends. Every guest frame is answered by exactly one.
#[derive(Debug, PartialEq, Eq)]
pub enum HostFrame {
    /// The answer to the `Decide` or `Redeem` numbered `seq`.
    Verdict { seq: Seq, verdict: Verdict },
    /// The `Observe` numbered `seq` has been folded into the host's label.
    Observed { seq: Seq },
    /// SHADOW MODE ONLY (P8): the `Shadow` report numbered `seq` was compared,
    /// and this is what the host found.
    Compared { seq: Seq, agreement: Agreement },
}
