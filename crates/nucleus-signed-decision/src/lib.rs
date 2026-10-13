//! Owner decisions an agent can verify.
//!
//! An approval says "this guardrail change may merge". A decision says "of these options for
//! this question, the owner chose this one". Without a format, a decision reaches an agent as
//! text, and any text can claim to be one: an issue comment, a brief, a memory file. This crate
//! is the format and the one verifier (design: the control plane's `docs/signed-decisions.md`).
//!
//! * [`record`] holds the proposal, the signed decision and the batch the owner's key signs, and
//!   their one encoding (a domain line plus `serde_json` in field order), with the round-trip
//!   that refuses any bytes that are not that encoding.
//! * [`verify`] is the only way to obtain a [`SignedDecision`]. It checks the signature against
//!   the operator's [`TrustRoots`], the canonical bytes, the tenant, the question and option
//!   digests, that the chosen option is one of them, that the scope is no wider than proposed,
//!   and the validity window.
//! * [`DecisionLedger`] holds verified decisions in one process. A standing decision is cited
//!   by id; a one-shot decision is spent, by value (ADR 0007 C-4), once; a superseded one is
//!   refused.
//!
//! What a decision authorizes is its `chosen` id among digests the owner was shown, and its
//! structured scope. Nothing here reads authority out of prose: `conditions` are the owner's
//! words and are signed, but they constrain and never widen.
//!
//! # What this does not claim
//!
//! * **Single use is per process.** [`DecisionLedger::spend`] refuses a second spend in the
//!   ledger that recorded the first. Fleet-wide single use needs one place that records spends,
//!   which is the merge gate, not this crate.
//! * **Supersession is what the ledger has seen.** A verifier offline from the control plane's
//!   log cannot see a superseding decision it was never given; until it is, the window is the
//!   bound.
//! * **No log inclusion proof is checked here.** The bundle's log fields (inclusion proof,
//!   witnessed checkpoint) are a later step; this verifies the owner's signature.

#![forbid(unsafe_code)]

mod key_ed25519;
mod key_p256;
mod ledger;
pub mod record;
mod roots;
mod scope;

#[cfg(test)]
mod tests;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

pub use ledger::{DecisionLedger, LedgerError, MAX_HELD, MAX_RETIRED, Spent};
pub use record::{
    DecisionBatch, OptionBody, OptionDigest, OwnerDecision, QuestionCore, Scope, decode_batch,
    option_sha256, question_sha256,
};
pub use roots::{MAX_ROOTS, RootsError, TrustRoots, kid_for};
pub use scope::{Action, Coverage, ScopeRef, WriteSet};

use record::{MAX_BATCH, MAX_OPTIONS, MAX_VALIDITY_SECS, MIN_OPTIONS};
use roots::SigRefusal;

/// A decision's id: `SHA-256(DECISION_DOMAIN || json(decision))`.
///
/// An id names a decision; it authorizes nothing. Only a [`SignedDecision`] with this id does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DecisionId(pub(crate) [u8; 32]);

impl DecisionId {
    /// Parse exactly 64 lowercase hex.
    pub fn from_hex(s: &str) -> Result<Self, DecisionError> {
        if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(DecisionError::BadId);
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).map_err(|_| DecisionError::BadId)?;
        Ok(Self(out))
    }

    /// 64 lowercase hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// The raw digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for DecisionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Why a bundle did not verify. Exhaustive; each arm is a distinct event (ADR 0007 A-8).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecisionError {
    /// A base64 field of the bundle is not standard base64.
    #[error("bundle field {field} is not base64")]
    BadEncoding {
        /// Which field.
        field: &'static str,
    },
    /// The bundle is not `{batch_b64, signature, index, question}` with no other fields.
    #[error("bundle is malformed: {0}")]
    BadBundle(String),
    /// No pinned key signed these bytes, and the batch names a kid that is pinned.
    #[error("signature does not verify against any trust root")]
    BadSignature,
    /// No pinned key signed these bytes, and the batch names a kid that is not pinned.
    #[error("kid {kid} is not a trust root")]
    UnknownKid {
        /// The kid the (unauthenticated) batch names.
        kid: String,
    },
    /// A pinned key signed the batch, and the batch names a different kid.
    #[error("batch names kid {claimed} but was signed by {signed_by}")]
    SignedByOtherKid {
        /// What the batch says.
        claimed: String,
        /// The root whose key verified.
        signed_by: String,
    },
    /// The signed bytes do not start with the batch domain.
    #[error("signed bytes are not an owner-decision batch")]
    WrongDomain,
    /// The signed bytes are not a batch.
    #[error("batch is malformed: {0}")]
    Malformed(String),
    /// The signed bytes parse, and do not re-serialize to themselves.
    #[error("batch bytes are not canonical")]
    NonCanonical,
    /// A record could not be encoded.
    #[error("record could not be encoded")]
    Unencodable,
    /// The batch is not 1 to 25 decisions in ascending `question_id` order with a 128-bit nonce.
    #[error("batch shape: {0}")]
    BatchShape(&'static str),
    /// The bundle's index is past the batch's last decision.
    #[error("index {index} is outside a batch of {len}")]
    IndexOutOfRange {
        /// The bundle's index.
        index: u64,
        /// How many decisions the batch holds.
        len: usize,
    },
    /// A decision is for another tenant.
    #[error("decision is for tenant {got}, expected {expected}")]
    WrongTenant {
        /// The verifier's tenant.
        expected: String,
        /// The decision's.
        got: String,
    },
    /// The bundle's question names another tenant, repository or question id.
    #[error("the bundled question is not the one decided")]
    QuestionNotBound,
    /// The question offers fewer than 2 or more than 8 options, or repeats an id.
    #[error("question shape: {0}")]
    QuestionShape(&'static str),
    /// The bundled question's options do not digest to the ones the owner signed: an option was
    /// edited, added, dropped or reordered after the owner saw it.
    #[error("the bundled options are not the ones the owner was shown")]
    OptionsMismatch,
    /// The bundled question does not digest to the one the owner signed.
    #[error("the bundled question is not the one the owner was shown")]
    QuestionMismatch,
    /// `chosen` is not exactly one of the listed option ids.
    #[error("chosen option {chosen} is not among the listed options")]
    ChosenNotAmongOptions {
        /// What the decision chose.
        chosen: String,
    },
    /// The decision's scope names something the proposal did not.
    #[error("scope item {item} is wider than proposed")]
    ScopeWiderThanProposed {
        /// The first item not in the proposed scope.
        item: String,
    },
    /// `supersedes` is not 64 lowercase hex.
    #[error("supersedes is not a decision id")]
    BadSupersedes,
    /// `not_after` precedes `valid_from`, or is more than 365 days after it.
    #[error("validity window is malformed")]
    BadWindow,
    /// The decision may not be relied on yet.
    #[error("decision is valid from {valid_from}, now is {now}")]
    NotYetValid {
        /// From when.
        valid_from: u64,
        /// The verifier's clock.
        now: u64,
    },
    /// The decision may no longer be relied on.
    #[error("decision expired at {not_after}, now is {now}")]
    Expired {
        /// Until when.
        not_after: u64,
        /// The verifier's clock.
        now: u64,
    },
    /// Not 64 lowercase hex.
    #[error("not a decision id")]
    BadId,
}

/// A decision's evidence as it travels: the signed batch, its signature, which entry is meant,
/// and the question body the owner was shown (so its digests can be recomputed here).
///
/// Untrusted bytes: the transport does not matter, and [`verify`] is what makes them evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionBundle {
    /// Standard base64 of the exact signed message (`BATCH_DOMAIN || json(batch)`).
    pub batch_b64: String,
    /// Standard base64 of the signature: X9.62 DER for P-256, 64 raw bytes for Ed25519.
    pub signature: String,
    /// Which of the batch's decisions this bundle is for.
    pub index: u64,
    /// The frozen question that decision answers.
    pub question: QuestionCore,
}

impl DecisionBundle {
    /// Parse a bundle file. Unknown fields are refused.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, DecisionError> {
        serde_json::from_slice(bytes).map_err(|e| DecisionError::BadBundle(e.to_string()))
    }
}

/// Where `now` sits in a decision's window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Window {
    /// `valid_from <= now <= not_after`.
    Live,
    /// `now < valid_from`.
    NotYetValid,
    /// `not_after < now`.
    Expired,
}

pub(crate) fn window_of(record: &OwnerDecision, now: u64) -> Window {
    if now < record.valid_from {
        Window::NotYetValid
    } else if now > record.not_after {
        Window::Expired
    } else {
        Window::Live
    }
}

fn window_error(record: &OwnerDecision, now: u64) -> Result<(), DecisionError> {
    match window_of(record, now) {
        Window::Live => Ok(()),
        Window::NotYetValid => Err(DecisionError::NotYetValid {
            valid_from: record.valid_from,
            now,
        }),
        Window::Expired => Err(DecisionError::Expired {
            not_after: record.not_after,
            now,
        }),
    }
}

/// A decision whose signature, canonical bytes, trust root, tenant, question binding, chosen
/// option, scope and window all verified.
///
/// Fields private; the only constructor is [`verify`] (ADR 0007 C-1). `!Clone`, `!Copy` (C-5):
/// a one-shot decision is spent by moving it into [`DecisionLedger::consume`] or by
/// [`DecisionLedger::spend`], never by borrowing it.
///
/// ```compile_fail
/// # fn f(d: nucleus_signed_decision::SignedDecision) {
/// let copy = d.clone(); // no Clone: a verified decision cannot be duplicated
/// # }
/// ```
#[derive(Debug)]
#[must_use = "a verified decision is evidence; hold it in a DecisionLedger or spend it"]
pub struct SignedDecision {
    id: DecisionId,
    record: OwnerDecision,
    question: QuestionCore,
    kid: String,
    who: String,
}

impl SignedDecision {
    /// The decision's id.
    pub const fn id(&self) -> DecisionId {
        self.id
    }

    /// The signed record.
    pub const fn record(&self) -> &OwnerDecision {
        &self.record
    }

    /// The question it answers, whose digest the record binds.
    pub const fn question(&self) -> &QuestionCore {
        &self.question
    }

    /// The full text of the chosen option. Always present on a verified decision.
    pub fn chosen_option(&self) -> Option<&OptionBody> {
        self.question
            .options
            .iter()
            .find(|o| o.id == self.record.chosen)
    }

    /// The trust root that signed it.
    pub fn kid(&self) -> &str {
        &self.kid
    }

    /// Who holds that root, as the operator's file names them. Not checked against anything.
    pub fn who(&self) -> &str {
        &self.who
    }

    /// The decision's canonical bytes, whose SHA-256 is its id.
    pub fn message(&self) -> Result<Vec<u8>, DecisionError> {
        self.record.message()
    }

    /// Where `now` sits in its window. Re-checked on every use, not only at [`verify`].
    pub fn window(&self, now: u64) -> Window {
        window_of(&self.record, now)
    }

    /// Is one item inside the signed scope?
    pub fn covers(&self, item: ScopeRef<'_>) -> Coverage {
        scope::covers(&self.record.scope, item)
    }

    /// Is an action (its capability and every path it writes) inside the signed scope?
    pub fn covers_action(&self, action: &Action<'_>) -> Coverage {
        scope::covers_action(&self.record.scope, action)
    }
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn decode_b64(field: &'static str, s: &str) -> Result<Vec<u8>, DecisionError> {
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|_| DecisionError::BadEncoding { field })
}

fn check_batch(batch: &DecisionBatch, tenant: &str) -> Result<(), DecisionError> {
    if batch.decisions.is_empty() || batch.decisions.len() > MAX_BATCH {
        return Err(DecisionError::BatchShape("1 to 25 decisions"));
    }
    if !is_lower_hex(&batch.nonce, 32) {
        return Err(DecisionError::BatchShape(
            "nonce is not 128 bits of lowercase hex",
        ));
    }
    if let Some(d) = batch.decisions.iter().find(|d| d.tenant != tenant) {
        return Err(DecisionError::WrongTenant {
            expected: tenant.to_string(),
            got: d.tenant.clone(),
        });
    }
    if batch
        .decisions
        .windows(2)
        .any(|w| w[0].question_id >= w[1].question_id)
    {
        return Err(DecisionError::BatchShape(
            "decisions are not strictly ascending by question_id",
        ));
    }
    Ok(())
}

fn check_decision(
    d: &OwnerDecision,
    question: &QuestionCore,
    now: u64,
) -> Result<(), DecisionError> {
    if question.tenant != d.tenant
        || question.repo != d.repo
        || question.question_id != d.question_id
    {
        return Err(DecisionError::QuestionNotBound);
    }
    let n = question.options.len();
    if !(MIN_OPTIONS..=MAX_OPTIONS).contains(&n) {
        return Err(DecisionError::QuestionShape("2 to 8 options"));
    }
    let mut ids = std::collections::BTreeSet::new();
    if !question.options.iter().all(|o| ids.insert(o.id.as_str())) {
        return Err(DecisionError::QuestionShape("an option id repeats"));
    }
    if OwnerDecision::option_digests_of(question)? != d.options {
        return Err(DecisionError::OptionsMismatch);
    }
    if question_sha256(question)? != d.question_sha256 {
        return Err(DecisionError::QuestionMismatch);
    }
    if d.options.iter().filter(|o| o.id == d.chosen).count() != 1 {
        return Err(DecisionError::ChosenNotAmongOptions {
            chosen: d.chosen.clone(),
        });
    }
    if let Some(item) = scope::first_widening(&d.scope, &question.proposed_scope) {
        return Err(DecisionError::ScopeWiderThanProposed {
            item: item.to_string(),
        });
    }
    if let Some(s) = &d.supersedes
        && !is_lower_hex(s, 64)
    {
        return Err(DecisionError::BadSupersedes);
    }
    if d.not_after < d.valid_from || d.not_after - d.valid_from > MAX_VALIDITY_SECS {
        return Err(DecisionError::BadWindow);
    }
    window_error(d, now)
}

/// Verify a bundle and mint the [`SignedDecision`] it carries. The only constructor.
///
/// In order, each a refusal by name: the signature over the received bytes against some pinned
/// key; the bytes' canonical round-trip; the batch naming the key that signed it; the batch's
/// shape and tenant; the bundled question's tenant, repository and id; its option digests, in
/// order, against the signed ones; its question digest; `chosen` among the options; the scope
/// within the proposal's; `supersedes`; the window's shape and `now` within it.
pub fn verify(
    bundle: &DecisionBundle,
    roots: &TrustRoots,
    now: u64,
    tenant: &str,
) -> Result<SignedDecision, DecisionError> {
    let message = decode_b64("batch_b64", &bundle.batch_b64)?;
    let signature = decode_b64("signature", &bundle.signature)?;

    let signer = roots
        .iter()
        .find(|r| match r.key.check(&message, &signature) {
            Ok(()) => true,
            Err(SigRefusal::Encoding | SigRefusal::DoesNotVerify) => false,
        });
    let Some(signer) = signer else {
        // Diagnostics only: these bytes are unauthenticated, and nothing below is reached.
        return Err(match decode_batch(&message) {
            Ok(b) if !roots.has_kid(&b.kid) => DecisionError::UnknownKid { kid: b.kid },
            Ok(_) | Err(_) => DecisionError::BadSignature,
        });
    };

    let batch = decode_batch(&message)?;
    if batch.kid != signer.kid {
        return Err(DecisionError::SignedByOtherKid {
            claimed: batch.kid,
            signed_by: signer.kid.clone(),
        });
    }
    check_batch(&batch, tenant)?;

    let len = batch.decisions.len();
    let record = usize::try_from(bundle.index)
        .ok()
        .and_then(|i| batch.decisions.into_iter().nth(i))
        .ok_or(DecisionError::IndexOutOfRange {
            index: bundle.index,
            len,
        })?;
    let id = record.decision_id()?;
    check_decision(&record, &bundle.question, now)?;

    Ok(SignedDecision {
        id,
        record,
        question: bundle.question.clone(),
        kid: signer.kid.clone(),
        who: signer.who.clone(),
    })
}
