//! The codec: one encoder and one total decoder per direction.
//!
//! # Layout
//!
//! ```text
//! frame  = len:u32be body[len]                      len <= MAX_BODY_LEN
//! body   = version:u8 tag:u8 seq:u64be payload
//!
//! guest tags                               payload
//!   0x01 Decide     op:u8 subject_len:u16be subject[subject_len] args_digest[32]
//!   0x02 Observe    label
//!   0x03 Redeem     approval_id
//! host tags
//!   0x81 Allowed            decision_id
//!   0x82 Denied             reason:u8
//!   0x83 ApprovalRequired   approval_id
//!   0x84 Observed           (empty)
//!
//! decision_id = approval_id = epoch:u64be number:u64be
//!
//! label  = confidentiality:u8 integrity:u8 provenance:u8
//!          observed_at:u64be ttl_secs:u64be authority:u8 derivation:u8
//! ```
//!
//! Every enum's wire byte is written once, in its `*_wire` function, as an
//! exhaustive match: a new variant upstream is a build error here until someone
//! gives it a byte. The decoder does not restate the bytes — it searches the
//! variant list for the one whose wire byte matches, so the two directions
//! cannot disagree about a value both know.
//!
//! The wire byte is deliberately NOT the in-memory discriminant (`as u8`): the
//! upstream discriminants are fixed for Aeneas, not for this protocol, and a
//! renumbering there must not silently renumber the wire.

use nucleus_ifc_kernel::{
    AuthorityLevel, ConfLevel, DerivationClass, Freshness, IFCLabel, IntegLevel, Operation,
    ProvenanceSet,
};

use crate::frame::{
    ApprovalId, ArgsDigest, DecisionId, DenyReason, GuestFrame, HostFrame, LabelRaise,
    MAX_SUBJECT_LEN, Seq, Subject, SubjectError, Verdict,
};

/// The protocol version this crate speaks. Any other version byte is refused.
pub const VERSION: u8 = 1;

/// Width of the big-endian `u32` length prefix in front of every body.
pub const LEN_PREFIX: usize = size_of::<u32>();

const VERSION_W: usize = size_of::<u8>();
const TAG_W: usize = size_of::<u8>();
const SEQ_W: usize = size_of::<u64>();
const OP_W: usize = size_of::<u8>();
const SUBJECT_LEN_W: usize = size_of::<u16>();

/// The longest body any frame can have: a `Decide` whose subject is
/// [`MAX_SUBJECT_LEN`] bytes. Derived from the field widths rather than written
/// as a number (ADR 0007 F-3); `max_decide_is_max_body` pins that it is reached.
pub const MAX_BODY_LEN: usize =
    VERSION_W + TAG_W + SEQ_W + OP_W + SUBJECT_LEN_W + MAX_SUBJECT_LEN + ArgsDigest::LEN;

/// Which field a decode error is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    LengthPrefix,
    Body,
    Version,
    Tag,
    Seq,
    Operation,
    SubjectLen,
    Subject,
    ArgsDigest,
    Confidentiality,
    Integrity,
    Provenance,
    ObservedAt,
    TtlSecs,
    Authority,
    Derivation,
    Epoch,
    DecisionId,
    ApprovalId,
    DenyReason,
}

/// Where unconsumed bytes were found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Region {
    /// After the body, inside the length the prefix declared: the body is
    /// longer than its variant.
    Body,
    /// After the frame: the buffer held more than one frame's worth.
    Stream,
}

/// Why bytes were refused as a frame. Every refusal has its own name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The length prefix declares a body longer than [`MAX_BODY_LEN`]. Refused
    /// before a single body byte is read or buffered.
    LengthPrefixTooLarge { declared: u32 },
    /// A body handed to `decode_body` is longer than [`MAX_BODY_LEN`].
    BodyTooLong { len: usize },
    /// A field ran past the end of the bytes available.
    Truncated {
        field: Field,
        needed: usize,
        available: usize,
    },
    /// Bytes were left over.
    TrailingBytes { region: Region, extra: usize },
    /// The version byte is not [`VERSION`].
    UnsupportedVersion { got: u8 },
    /// The tag names no frame in this direction. A host frame sent to the host
    /// lands here: the guest and host tag sets are disjoint.
    UnknownTag { got: u8 },
    /// An enum field carried a byte no variant encodes to.
    UnknownDiscriminant { field: Field, got: u8 },
    /// The provenance byte set bits the provenance lattice has no source for.
    ProvenanceOutOfRange { got: u8 },
    /// The subject's declared length exceeds [`MAX_SUBJECT_LEN`].
    SubjectTooLong { len: usize },
    /// The subject is not UTF-8.
    SubjectNotUtf8,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::LengthPrefixTooLarge { declared } => write!(
                f,
                "length prefix declares {declared} bytes (max {MAX_BODY_LEN})"
            ),
            FrameError::BodyTooLong { len } => {
                write!(f, "body is {len} bytes (max {MAX_BODY_LEN})")
            }
            FrameError::Truncated {
                field,
                needed,
                available,
            } => write!(
                f,
                "truncated at {field:?}: needed {needed} bytes, {available} available"
            ),
            FrameError::TrailingBytes { region, extra } => {
                write!(f, "{extra} trailing bytes after the {region:?}")
            }
            FrameError::UnsupportedVersion { got } => {
                write!(f, "unsupported version {got} (this side speaks {VERSION})")
            }
            FrameError::UnknownTag { got } => write!(f, "unknown frame tag {got:#04x}"),
            FrameError::UnknownDiscriminant { field, got } => {
                write!(f, "unknown {field:?} value {got:#04x}")
            }
            FrameError::ProvenanceOutOfRange { got } => {
                write!(f, "provenance {got:#04x} sets bits outside the lattice")
            }
            FrameError::SubjectTooLong { len } => {
                write!(f, "subject is {len} bytes (max {MAX_SUBJECT_LEN})")
            }
            FrameError::SubjectNotUtf8 => write!(f, "subject is not UTF-8"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Why a frame could not be encoded.
///
/// Unreachable for any frame built through this crate's constructors — a
/// [`Subject`] is bounded at construction and every other field is fixed-width
/// — and kept as a value rather than a panic so the encoder is total too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    /// The subject does not fit its `u16` length field.
    SubjectTooLong { len: usize },
    /// The body exceeds [`MAX_BODY_LEN`].
    BodyTooLong { len: usize },
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeError::SubjectTooLong { len } => {
                write!(f, "subject of {len} bytes does not fit a u16 length")
            }
            EncodeError::BodyTooLong { len } => {
                write!(f, "body of {len} bytes exceeds {MAX_BODY_LEN}")
            }
        }
    }
}

impl std::error::Error for EncodeError {}

/// The body length a 4-byte prefix declares, or a refusal if it is over
/// [`MAX_BODY_LEN`].
///
/// For the I/O layer: read [`LEN_PREFIX`] bytes, call this, and only then
/// buffer the body — so a guest that declares 4 GiB costs the host four bytes.
pub fn body_len(prefix: [u8; LEN_PREFIX]) -> Result<usize, FrameError> {
    let declared = u32::from_be_bytes(prefix);
    match usize::try_from(declared) {
        Ok(len) if len <= MAX_BODY_LEN => Ok(len),
        Ok(_) | Err(_) => Err(FrameError::LengthPrefixTooLarge { declared }),
    }
}

// ── tags ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuestTag {
    Decide,
    Observe,
    Redeem,
}

impl GuestTag {
    pub(crate) const ALL: [GuestTag; 3] = [GuestTag::Decide, GuestTag::Observe, GuestTag::Redeem];

    pub(crate) const fn wire(self) -> u8 {
        match self {
            GuestTag::Decide => 0x01,
            GuestTag::Observe => 0x02,
            GuestTag::Redeem => 0x03,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostTag {
    Allowed,
    Denied,
    ApprovalRequired,
    Observed,
}

impl HostTag {
    pub(crate) const ALL: [HostTag; 4] = [
        HostTag::Allowed,
        HostTag::Denied,
        HostTag::ApprovalRequired,
        HostTag::Observed,
    ];

    pub(crate) const fn wire(self) -> u8 {
        match self {
            HostTag::Allowed => 0x81,
            HostTag::Denied => 0x82,
            HostTag::ApprovalRequired => 0x83,
            HostTag::Observed => 0x84,
        }
    }
}

// ── enum wire bytes: written once each, as an exhaustive match ─────────────

pub(crate) const fn op_wire(op: Operation) -> u8 {
    match op {
        Operation::ReadFiles => 0,
        Operation::WriteFiles => 1,
        Operation::EditFiles => 2,
        Operation::RunBash => 3,
        Operation::GlobSearch => 4,
        Operation::GrepSearch => 5,
        Operation::WebSearch => 6,
        Operation::WebFetch => 7,
        Operation::GitCommit => 8,
        Operation::GitPush => 9,
        Operation::CreatePr => 10,
        Operation::ManagePods => 11,
        Operation::SpawnAgent => 12,
    }
}

pub(crate) const CONF_ALL: [ConfLevel; 3] =
    [ConfLevel::Public, ConfLevel::Internal, ConfLevel::Secret];

pub(crate) const fn conf_wire(c: ConfLevel) -> u8 {
    match c {
        ConfLevel::Public => 0,
        ConfLevel::Internal => 1,
        ConfLevel::Secret => 2,
    }
}

pub(crate) const INTEG_ALL: [IntegLevel; 3] = [
    IntegLevel::Adversarial,
    IntegLevel::Untrusted,
    IntegLevel::Trusted,
];

pub(crate) const fn integ_wire(i: IntegLevel) -> u8 {
    match i {
        IntegLevel::Adversarial => 0,
        IntegLevel::Untrusted => 1,
        IntegLevel::Trusted => 2,
    }
}

pub(crate) const AUTHORITY_ALL: [AuthorityLevel; 4] = [
    AuthorityLevel::NoAuthority,
    AuthorityLevel::Informational,
    AuthorityLevel::Suggestive,
    AuthorityLevel::Directive,
];

pub(crate) const fn authority_wire(a: AuthorityLevel) -> u8 {
    match a {
        AuthorityLevel::NoAuthority => 0,
        AuthorityLevel::Informational => 1,
        AuthorityLevel::Suggestive => 2,
        AuthorityLevel::Directive => 3,
    }
}

pub(crate) const DERIVATION_ALL: [DerivationClass; 5] = [
    DerivationClass::Deterministic,
    DerivationClass::AIDerived,
    DerivationClass::Mixed,
    DerivationClass::HumanPromoted,
    DerivationClass::OpaqueExternal,
];

pub(crate) const fn derivation_wire(d: DerivationClass) -> u8 {
    match d {
        DerivationClass::Deterministic => 0,
        DerivationClass::AIDerived => 1,
        DerivationClass::Mixed => 2,
        DerivationClass::HumanPromoted => 3,
        DerivationClass::OpaqueExternal => 4,
    }
}

pub(crate) const fn deny_wire(r: DenyReason) -> u8 {
    match r {
        DenyReason::NotGranted => 0,
        DenyReason::FlowRefused => 1,
        DenyReason::BudgetExhausted => 2,
        DenyReason::ApprovalRefused => 3,
        DenyReason::ApprovalExpired => 4,
        DenyReason::ApprovalUnknown => 5,
    }
}

/// The variant of `all` whose wire byte is `got`, or a named refusal.
fn from_wire<T: Copy>(
    all: &[T],
    wire: fn(T) -> u8,
    got: u8,
    field: Field,
) -> Result<T, FrameError> {
    all.iter()
        .copied()
        .find(|v| wire(*v) == got)
        .ok_or(FrameError::UnknownDiscriminant { field, got })
}

// ── reading ─────────────────────────────────────────────────────────────────

/// A cursor that only ever moves forward through a borrowed slice. Every read
/// is checked; none indexes.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    fn take(&mut self, n: usize, field: Field) -> Result<&'a [u8], FrameError> {
        match self.rest.split_at_checked(n) {
            Some((head, tail)) => {
                self.rest = tail;
                Ok(head)
            }
            None => Err(FrameError::Truncated {
                field,
                needed: n,
                available: self.rest.len(),
            }),
        }
    }

    fn array<const N: usize>(&mut self, field: Field) -> Result<[u8; N], FrameError> {
        match self.rest.split_first_chunk::<N>() {
            Some((head, tail)) => {
                self.rest = tail;
                Ok(*head)
            }
            None => Err(FrameError::Truncated {
                field,
                needed: N,
                available: self.rest.len(),
            }),
        }
    }

    fn u8(&mut self, field: Field) -> Result<u8, FrameError> {
        let [b] = self.array::<1>(field)?;
        Ok(b)
    }

    fn u16(&mut self, field: Field) -> Result<u16, FrameError> {
        self.array(field).map(u16::from_be_bytes)
    }

    fn u64(&mut self, field: Field) -> Result<u64, FrameError> {
        self.array(field).map(u64::from_be_bytes)
    }

    fn finish(self, region: Region) -> Result<(), FrameError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(FrameError::TrailingBytes {
                region,
                extra: self.rest.len(),
            })
        }
    }
}

/// Split one length-prefixed frame into its body, refusing an oversize prefix
/// before the body is touched and any byte after the frame.
fn unframe(frame: &[u8]) -> Result<&[u8], FrameError> {
    let mut r = Reader::new(frame);
    let len = body_len(r.array::<LEN_PREFIX>(Field::LengthPrefix)?)?;
    let body = r.take(len, Field::Body)?;
    r.finish(Region::Stream)?;
    Ok(body)
}

/// Open a body: bound, version, then the tag byte (still raw).
fn open_body(body: &[u8]) -> Result<(Reader<'_>, u8), FrameError> {
    if body.len() > MAX_BODY_LEN {
        return Err(FrameError::BodyTooLong { len: body.len() });
    }
    let mut r = Reader::new(body);
    let version = r.u8(Field::Version)?;
    if version != VERSION {
        return Err(FrameError::UnsupportedVersion { got: version });
    }
    let tag = r.u8(Field::Tag)?;
    Ok((r, tag))
}

fn read_subject(r: &mut Reader<'_>) -> Result<Subject, FrameError> {
    let len = usize::from(r.u16(Field::SubjectLen)?);
    // Refuse on the declared length, before reading the bytes it claims.
    if len > MAX_SUBJECT_LEN {
        return Err(FrameError::SubjectTooLong { len });
    }
    let bytes = r.take(len, Field::Subject)?;
    let text = std::str::from_utf8(bytes).map_err(|_| FrameError::SubjectNotUtf8)?;
    match Subject::new(text) {
        Ok(subject) => Ok(subject),
        Err(SubjectError::TooLong { len }) => Err(FrameError::SubjectTooLong { len }),
    }
}

fn read_label(r: &mut Reader<'_>) -> Result<IFCLabel, FrameError> {
    let confidentiality = from_wire(
        &CONF_ALL,
        conf_wire,
        r.u8(Field::Confidentiality)?,
        Field::Confidentiality,
    )?;
    let integrity = from_wire(
        &INTEG_ALL,
        integ_wire,
        r.u8(Field::Integrity)?,
        Field::Integrity,
    )?;
    let bits = r.u8(Field::Provenance)?;
    let provenance = ProvenanceSet::from_bits(bits);
    // `from_bits` silently drops bits it has no source for. On the wire that is
    // a frame that does not mean what it says, so it is refused instead.
    if provenance.bits() != bits {
        return Err(FrameError::ProvenanceOutOfRange { got: bits });
    }
    let observed_at = r.u64(Field::ObservedAt)?;
    let ttl_secs = r.u64(Field::TtlSecs)?;
    let authority = from_wire(
        &AUTHORITY_ALL,
        authority_wire,
        r.u8(Field::Authority)?,
        Field::Authority,
    )?;
    let derivation = from_wire(
        &DERIVATION_ALL,
        derivation_wire,
        r.u8(Field::Derivation)?,
        Field::Derivation,
    )?;
    // A full struct literal: a field added to IFCLabel is a build error here.
    Ok(IFCLabel {
        confidentiality,
        integrity,
        provenance,
        freshness: Freshness {
            observed_at,
            ttl_secs,
        },
        authority,
        derivation,
    })
}

// ── writing ─────────────────────────────────────────────────────────────────

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// An id on the wire: its ledger's epoch, then its number. Takes the two
/// numbers rather than the id, so writing one is plainly a read of it.
fn put_id(out: &mut Vec<u8>, epoch: u64, number: u64) {
    put_u64(out, epoch);
    put_u64(out, number);
}

fn read_approval(r: &mut Reader<'_>) -> Result<ApprovalId, FrameError> {
    let epoch = r.u64(Field::Epoch)?;
    let number = r.u64(Field::ApprovalId)?;
    Ok(ApprovalId::mint(epoch, number))
}

fn put_label(out: &mut Vec<u8>, label: IFCLabel) {
    // No `..`: a field added to IFCLabel is a build error here (ADR 0007 E-1).
    let IFCLabel {
        confidentiality,
        integrity,
        provenance,
        freshness: Freshness {
            observed_at,
            ttl_secs,
        },
        authority,
        derivation,
    } = label;
    out.push(conf_wire(confidentiality));
    out.push(integ_wire(integrity));
    out.push(provenance.bits());
    put_u64(out, observed_at);
    put_u64(out, ttl_secs);
    out.push(authority_wire(authority));
    out.push(derivation_wire(derivation));
}

fn header(tag: u8, seq: Seq) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(VERSION);
    body.push(tag);
    put_u64(&mut body, seq.get());
    body
}

/// Prefix a finished body with its length.
fn frame(body: Vec<u8>) -> Result<Vec<u8>, EncodeError> {
    let len = body.len();
    if len > MAX_BODY_LEN {
        return Err(EncodeError::BodyTooLong { len });
    }
    let declared = u32::try_from(len).map_err(|_| EncodeError::BodyTooLong { len })?;
    let mut out = Vec::with_capacity(LEN_PREFIX.saturating_add(len));
    out.extend_from_slice(&declared.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

// ── the public codec ────────────────────────────────────────────────────────

impl GuestFrame {
    /// The frame's bytes, length prefix included.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let body = match self {
            GuestFrame::Decide {
                seq,
                op,
                subject,
                args_digest,
            } => {
                let mut body = header(GuestTag::Decide.wire(), *seq);
                body.push(op_wire(*op));
                let text = subject.as_str().as_bytes();
                let len = u16::try_from(text.len())
                    .map_err(|_| EncodeError::SubjectTooLong { len: text.len() })?;
                body.extend_from_slice(&len.to_be_bytes());
                body.extend_from_slice(text);
                body.extend_from_slice(args_digest.as_bytes());
                body
            }
            GuestFrame::Observe { seq, label_raise } => {
                let mut body = header(GuestTag::Observe.wire(), *seq);
                put_label(&mut body, label_raise.wire_label());
                body
            }
            GuestFrame::Redeem { seq, approval_id } => {
                let mut body = header(GuestTag::Redeem.wire(), *seq);
                put_id(&mut body, approval_id.epoch(), approval_id.number());
                body
            }
        };
        frame(body)
    }

    /// Decode exactly one length-prefixed frame. Anything after it is refused.
    pub fn decode(frame: &[u8]) -> Result<Self, FrameError> {
        Self::decode_body(unframe(frame)?)
    }

    /// Decode a body whose length prefix the I/O layer has already read and
    /// checked with [`body_len`].
    pub fn decode_body(body: &[u8]) -> Result<Self, FrameError> {
        let (mut r, got) = open_body(body)?;
        let tag = GuestTag::ALL
            .into_iter()
            .find(|t| t.wire() == got)
            .ok_or(FrameError::UnknownTag { got })?;
        let seq = Seq::new(r.u64(Field::Seq)?);
        let frame = match tag {
            GuestTag::Decide => {
                let op = from_wire(
                    &Operation::ALL,
                    op_wire,
                    r.u8(Field::Operation)?,
                    Field::Operation,
                )?;
                let subject = read_subject(&mut r)?;
                let args_digest = ArgsDigest::new(r.array(Field::ArgsDigest)?);
                GuestFrame::Decide {
                    seq,
                    op,
                    subject,
                    args_digest,
                }
            }
            GuestTag::Observe => GuestFrame::Observe {
                seq,
                label_raise: LabelRaise::new(read_label(&mut r)?),
            },
            GuestTag::Redeem => GuestFrame::Redeem {
                seq,
                approval_id: read_approval(&mut r)?,
            },
        };
        r.finish(Region::Body)?;
        Ok(frame)
    }

    /// The host-assigned number this frame claims.
    pub fn seq(&self) -> Seq {
        match self {
            GuestFrame::Decide { seq, .. }
            | GuestFrame::Observe { seq, .. }
            | GuestFrame::Redeem { seq, .. } => *seq,
        }
    }
}

impl HostFrame {
    /// The frame's bytes, length prefix included.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let body = match self {
            HostFrame::Verdict { seq, verdict } => match verdict {
                Verdict::Allowed { decision_id } => {
                    let mut body = header(HostTag::Allowed.wire(), *seq);
                    put_id(&mut body, decision_id.epoch(), decision_id.number());
                    body
                }
                Verdict::Denied { reason } => {
                    let mut body = header(HostTag::Denied.wire(), *seq);
                    body.push(deny_wire(*reason));
                    body
                }
                Verdict::ApprovalRequired { approval_id } => {
                    let mut body = header(HostTag::ApprovalRequired.wire(), *seq);
                    put_id(&mut body, approval_id.epoch(), approval_id.number());
                    body
                }
            },
            HostFrame::Observed { seq } => header(HostTag::Observed.wire(), *seq),
        };
        frame(body)
    }

    /// Decode exactly one length-prefixed frame. Anything after it is refused.
    pub fn decode(frame: &[u8]) -> Result<Self, FrameError> {
        Self::decode_body(unframe(frame)?)
    }

    /// Decode a body whose length prefix the I/O layer has already read and
    /// checked with [`body_len`].
    pub fn decode_body(body: &[u8]) -> Result<Self, FrameError> {
        let (mut r, got) = open_body(body)?;
        let tag = HostTag::ALL
            .into_iter()
            .find(|t| t.wire() == got)
            .ok_or(FrameError::UnknownTag { got })?;
        let seq = Seq::new(r.u64(Field::Seq)?);
        let frame = match tag {
            HostTag::Allowed => HostFrame::Verdict {
                seq,
                verdict: Verdict::Allowed {
                    decision_id: {
                        let epoch = r.u64(Field::Epoch)?;
                        DecisionId::mint(epoch, r.u64(Field::DecisionId)?)
                    },
                },
            },
            HostTag::Denied => HostFrame::Verdict {
                seq,
                verdict: Verdict::Denied {
                    reason: from_wire(
                        &DenyReason::ALL,
                        deny_wire,
                        r.u8(Field::DenyReason)?,
                        Field::DenyReason,
                    )?,
                },
            },
            HostTag::ApprovalRequired => HostFrame::Verdict {
                seq,
                verdict: Verdict::ApprovalRequired {
                    approval_id: read_approval(&mut r)?,
                },
            },
            HostTag::Observed => HostFrame::Observed { seq },
        };
        r.finish(Region::Body)?;
        Ok(frame)
    }

    /// The number of the guest frame this answers.
    pub fn seq(&self) -> Seq {
        match self {
            HostFrame::Verdict { seq, .. } | HostFrame::Observed { seq } => *seq,
        }
    }
}

#[cfg(test)]
pub(crate) mod wire_tables {
    //! The codec's private tables, for the tests' exhaustiveness checks.
    pub(crate) use super::{
        AUTHORITY_ALL, CONF_ALL, DERIVATION_ALL, GuestTag, HostTag, INTEG_ALL, authority_wire,
        conf_wire, deny_wire, derivation_wire, integ_wire, op_wire,
    };
}
