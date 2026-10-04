//! The per-pod decision channel: one wire declaration for the guest and the host.
//!
//! Part of the host-decides programme (#2702, L-1, step P7). Today every
//! decision about a tool call is taken inside the guest, by a process that also
//! holds the receipt-signing key. The programme moves the deciding to the host;
//! this crate is the protocol it moves over. It is not wired in yet — P8 adds the
//! host's shadow decide — so nothing here changes behaviour on its own.
//!
//! # The conversation
//!
//! The guest sends a [`GuestFrame`] and the host answers it with exactly one
//! [`HostFrame`]:
//!
//! | guest asks | host answers |
//! |---|---|
//! | [`GuestFrame::Decide`] — may I do `op` to `subject` with args hashing to `args_digest`? | [`HostFrame::Verdict`]: [`Verdict::Allowed`] with a [`DecisionId`], [`Verdict::Denied`] with a [`DenyReason`], or [`Verdict::ApprovalRequired`] with an [`ApprovalId`] |
//! | [`GuestFrame::Observe`] — I have seen something; raise my taint by this | [`HostFrame::Observed`] |
//! | [`GuestFrame::Redeem`] — the approval I was told to wait for | [`HostFrame::Verdict`], allowed or denied |
//!
//! # Who decides what
//!
//! * **The host numbers the conversation.** [`Seq`] is the host's count of
//!   frames on this channel; [`host::SeqGate`] admits exactly the next one and
//!   refuses a replay, a gap or a wrap. The guest echoes the number; it does not
//!   choose it.
//! * **The host mints decision ids.** A [`DecisionId`] has no public
//!   constructor, is `!Clone` and `!Copy`, and the only thing that accepts one —
//!   [`host::DecisionLedger::consume`] — takes it by value (ADR 0007 C-1, C-4,
//!   C-5). Because bytes can always be decoded twice, the type alone cannot stop
//!   a guest replaying a frame; the ledger can, and does: a second consume of the
//!   same id is [`host::LedgerError::Retired`]. Every id also carries its
//!   ledger's epoch, so an id from a closed channel is
//!   [`host::LedgerError::ForeignEpoch`] on the channel that replaced it rather
//!   than a live number on a ledger that also started from zero.
//! * **Taint is the host's, and the guest can only raise it** (owner decision
//!   D2). [`LabelRaise`] has one consumer, [`LabelRaise::raise`], and it is the
//!   lattice join — an upper bound of what the host already holds. There is no
//!   value of the type that lowers a label, so no frame can carry one.
//!
//! # The wire
//!
//! `u32` big-endian body length, then the body: a version byte, a tag byte, the
//! host's sequence number, and the variant's fields at fixed widths (the subject
//! alone is `u16`-length-prefixed). The parser is total, bounded and
//! fail-closed, held to the same contract as
//! `nucleus-node/src/workload_api_protocol.rs`: it rejects an oversize length
//! before reading the body, an unknown version, tag or discriminant, a truncated
//! field, and a trailing byte after the body or after the frame — each with a
//! named [`FrameError`], never a panic. Guest and host tags are disjoint, so a
//! host frame reflected back at the host is an unknown tag, not a request.
//!
//! The encoding is canonical: every value has exactly one encoding, so
//! `encode(decode(bytes)) == bytes` for every accepted input. The fuzz target
//! asserts exactly that.
//!
//! ## Why hand-written and not derived (ADR 0007 F-1)
//!
//! F-1 asks for derived serialization so that a dropped field is unwritable.
//! Here the same property comes from the compiler a different way: the encoder
//! destructures every record with no `..` (E-1) and the decoder builds every
//! record with a full struct literal, so a field added to a frame — or to
//! `IFCLabel` upstream — is a build error on both sides until someone decides
//! its encoding. What a derive would NOT give is what this boundary needs: a
//! decoder that refuses `ProvenanceSet` bits the lattice has no meaning for
//! (the derived impl accepts any `u8`), a named error per failure, and an
//! allocation bounded before any guest byte is interpreted.

#![forbid(unsafe_code)]
// Declared panic-free for the shipped build (the scorecard's `tot` family). This
// crate parses bytes a possibly-hostile guest wrote; a decoder that can panic is
// a host DoS, and one that can wrap is worse.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::unreachable,
        clippy::todo
    )
)]

mod codec;
mod frame;
pub mod host;

pub use codec::{
    EncodeError, Field, FrameError, LEN_PREFIX, MAX_BODY_LEN, Region, VERSION, body_len,
};
pub use frame::{
    ApprovalId, ArgsDigest, DecisionId, DenyReason, GuestFrame, HostFrame, LabelRaise,
    MAX_SUBJECT_LEN, Seq, Subject, SubjectError, Verdict,
};

/// The label and operation vocabulary, re-exported so a consumer names the
/// same types this protocol carries without a second dependency line.
pub use nucleus_ifc_kernel::{
    AuthorityLevel, ConfLevel, DerivationClass, Freshness, IFCLabel, IntegLevel, Operation,
    ProvenanceSet,
};

#[cfg(test)]
mod tests;
