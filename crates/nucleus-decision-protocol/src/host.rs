//! The host's half: who numbers the frames and who mints and retires ids.
//!
//! Pure state machines, no I/O. P8 holds one [`SeqGate`] and one
//! [`DecisionLedger`] per pod channel.
//!
//! The guest links this module too (it is one crate), and that grants it
//! nothing: a ledger the guest builds is a ledger nobody consults. What makes
//! an id good is that the host's own ledger issued it and has not retired it.

use std::collections::{BTreeMap, BTreeSet};

use crate::frame::{ApprovalId, DecisionId, Seq};

/// Admits guest frames strictly in the host's order.
///
/// The channel's numbering starts at [`Seq::FIRST`] and the gate accepts only
/// the next number: a repeat is a replay, a jump is a gap, and both are refused
/// with the number the host expected. A refusal does not advance the gate.
#[derive(Debug)]
pub struct SeqGate {
    /// `None` once the channel has carried `u64::MAX + 1` frames.
    next: Option<Seq>,
}

/// Why a frame's sequence number was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqError {
    /// A number the host has already admitted.
    Replayed { expected: Seq, got: Seq },
    /// A number past the one the host expects.
    Skipped { expected: Seq, got: Seq },
    /// The channel has used every number; it must be closed, not wrapped.
    Exhausted { got: Seq },
}

impl std::fmt::Display for SeqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeqError::Replayed { expected, got } => write!(
                f,
                "frame {} replayed (expected {})",
                got.get(),
                expected.get()
            ),
            SeqError::Skipped { expected, got } => write!(
                f,
                "frame {} skips ahead (expected {})",
                got.get(),
                expected.get()
            ),
            SeqError::Exhausted { got } => {
                write!(f, "frame {} after the channel's numbers ran out", got.get())
            }
        }
    }
}

impl std::error::Error for SeqError {}

impl SeqGate {
    /// A gate for a fresh channel, expecting [`Seq::FIRST`].
    pub const fn new() -> Self {
        Self {
            next: Some(Seq::FIRST),
        }
    }

    /// The number the host will admit next, or `None` if the channel is spent.
    pub const fn expected(&self) -> Option<Seq> {
        self.next
    }

    /// Admit `got` if it is exactly the next number.
    pub fn admit(&mut self, got: Seq) -> Result<(), SeqError> {
        let Some(expected) = self.next else {
            return Err(SeqError::Exhausted { got });
        };
        match got.cmp(&expected) {
            std::cmp::Ordering::Equal => {
                self.next = expected.next();
                Ok(())
            }
            std::cmp::Ordering::Less => Err(SeqError::Replayed { expected, got }),
            std::cmp::Ordering::Greater => Err(SeqError::Skipped { expected, got }),
        }
    }
}

impl Default for SeqGate {
    /// A fresh channel. Not a permissive default: the only state it can
    /// produce is "expect the first frame".
    fn default() -> Self {
        Self::new()
    }
}

/// The most ids a channel may hold live at once: decisions allowed but not yet
/// consumed, plus approvals not yet redeemed. A guest that asks without ever
/// acting is refused past this, so it cannot grow the host's memory.
pub const MAX_LIVE: usize = 1024;

/// Proof the host retired a [`DecisionId`]: the one value a consumed id leaves
/// behind, carrying its number for the receipt (P10).
///
/// Minted only by [`DecisionLedger::consume`], and carrying the issuing
/// ledger's epoch so a receipt names which channel's decision it records.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a Spent is the record that the decision was used; carry it to the receipt"]
pub struct Spent {
    epoch: u64,
    decision: u64,
}

impl Spent {
    /// The epoch of the ledger that issued and retired the decision.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The number of the decision this retired.
    pub const fn decision(&self) -> u64 {
        self.decision
    }
}

/// What a redemption found.
#[derive(Debug, PartialEq, Eq)]
pub enum Redemption {
    /// A human granted it: here is the one decision it was reserved for, now
    /// live. The approval is retired.
    Granted(DecisionId),
    /// A human refused it. The approval and its reserved decision are retired.
    Refused,
    /// Nobody has decided yet. The handle comes back, because the approval is
    /// still live and the holder will need it to redeem again.
    Pending(ApprovalId),
}

/// Why the ledger refused an id.
///
/// "Was issued and is no longer live" and "was never issued" are different
/// variants because they are different events (ADR 0007 A-8): the first is a
/// replay, the second a forgery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    /// The id was issued by a different ledger — another channel, or this
    /// pod's channel before a reconnect. Refused before its number is read.
    ForeignEpoch { expected: u64, got: u64 },
    /// This decision id was issued here and has been consumed, or its approval
    /// was refused. Presenting it again is a replay.
    Retired { decision: u64 },
    /// This decision id is reserved for an approval that has not been redeemed.
    /// It is not usable until it is.
    AwaitingApproval { decision: u64 },
    /// No decision with this number was ever issued on this channel.
    NeverIssued { decision: u64 },
    /// This approval was issued here and is no longer live: already redeemed,
    /// or refused.
    ApprovalRetired { approval: u64 },
    /// No approval with this number was ever issued on this channel.
    ApprovalNeverIssued { approval: u64 },
    /// [`MAX_LIVE`] ids are already live.
    TooManyLive,
    /// The channel has used every id number; it must be closed.
    Exhausted,
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LedgerError::ForeignEpoch { expected, got } => {
                write!(f, "id from ledger epoch {got}, this ledger is {expected}")
            }
            LedgerError::Retired { decision } => {
                write!(f, "decision {decision} was already used (replay)")
            }
            LedgerError::AwaitingApproval { decision } => {
                write!(f, "decision {decision} is waiting on an approval")
            }
            LedgerError::NeverIssued { decision } => {
                write!(f, "decision {decision} was never issued (forged)")
            }
            LedgerError::ApprovalRetired { approval } => {
                write!(f, "approval {approval} was already redeemed or refused")
            }
            LedgerError::ApprovalNeverIssued { approval } => {
                write!(f, "approval {approval} was never issued (forged)")
            }
            LedgerError::TooManyLive => write!(f, "more than {MAX_LIVE} live ids"),
            LedgerError::Exhausted => write!(f, "the channel's id numbers ran out"),
        }
    }
}

impl std::error::Error for LedgerError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalState {
    Pending,
    Granted,
    Refused,
}

#[derive(Debug)]
struct Reservation {
    decision: u64,
    state: ApprovalState,
}

/// The host's register of decision and approval ids on one channel.
///
/// The only minter of [`DecisionId`] and [`ApprovalId`] on the host, and the
/// only consumer of either. It holds the live ids and nothing else, so its size
/// is bounded by [`MAX_LIVE`], not by how long the pod has run: a retired id is
/// recognised as retired because its number is below the next one to issue
/// and it is not live.
///
/// # The epoch
///
/// Every ledger numbers its ids from zero, so a number alone cannot say which
/// ledger issued it. The epoch can: every id carries its issuer's, and every
/// consumer here refuses a foreign one first. The host must give each channel's
/// ledger an epoch no earlier channel on the node used — a node-wide counter,
/// or a random `u64` — or a reconnect reopens decision 0.
#[derive(Debug)]
pub struct DecisionLedger {
    epoch: u64,
    next_decision: u64,
    next_approval: u64,
    /// Allowed, not yet consumed.
    live: BTreeSet<u64>,
    /// Approval number -> the decision it reserves, and what the human said.
    approvals: BTreeMap<u64, Reservation>,
}

impl DecisionLedger {
    /// An empty ledger for a fresh channel, issuing under `epoch`.
    pub const fn new(epoch: u64) -> Self {
        Self {
            epoch,
            next_decision: 0,
            next_approval: 0,
            live: BTreeSet::new(),
            approvals: BTreeMap::new(),
        }
    }

    fn live_count(&self) -> usize {
        self.live.len().saturating_add(self.approvals.len())
    }

    fn take_decision_number(&mut self) -> Result<u64, LedgerError> {
        if self.live_count() >= MAX_LIVE {
            return Err(LedgerError::TooManyLive);
        }
        let n = self.next_decision;
        self.next_decision = n.checked_add(1).ok_or(LedgerError::Exhausted)?;
        Ok(n)
    }

    /// The host has decided to allow an operation: mint its one-shot id.
    pub fn allow(&mut self) -> Result<DecisionId, LedgerError> {
        let n = self.take_decision_number()?;
        self.live.insert(n);
        Ok(DecisionId::mint(self.epoch, n))
    }

    /// The epoch every id this ledger issues carries.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    fn check_epoch(&self, got: u64) -> Result<(), LedgerError> {
        if got == self.epoch {
            Ok(())
        } else {
            Err(LedgerError::ForeignEpoch {
                expected: self.epoch,
                got,
            })
        }
    }

    /// The host requires a human approval: reserve the decision the approval
    /// will become, and mint the handle that redeems it.
    pub fn require_approval(&mut self) -> Result<ApprovalId, LedgerError> {
        let a = self.next_approval;
        let next_approval = a.checked_add(1).ok_or(LedgerError::Exhausted)?;
        let decision = self.take_decision_number()?;
        self.next_approval = next_approval;
        self.approvals.insert(
            a,
            Reservation {
                decision,
                state: ApprovalState::Pending,
            },
        );
        Ok(ApprovalId::mint(self.epoch, a))
    }

    fn approval_error(&self, approval: u64) -> LedgerError {
        if approval < self.next_approval {
            LedgerError::ApprovalRetired { approval }
        } else {
            LedgerError::ApprovalNeverIssued { approval }
        }
    }

    fn settle(&mut self, approval: u64, to: ApprovalState) -> Result<(), LedgerError> {
        match self.approvals.get_mut(&approval) {
            Some(r) if r.state == ApprovalState::Pending => {
                r.state = to;
                Ok(())
            }
            // Already settled: a human decision is not revisable through here.
            Some(_) => Err(LedgerError::ApprovalRetired { approval }),
            None => Err(self.approval_error(approval)),
        }
    }

    /// A human granted approval number `approval`.
    ///
    /// Takes the number, not the handle: the approver is shown a number, and
    /// the handle stays with whoever will redeem it.
    pub fn grant(&mut self, approval: u64) -> Result<(), LedgerError> {
        self.settle(approval, ApprovalState::Granted)
    }

    /// A human refused approval number `approval`.
    pub fn refuse(&mut self, approval: u64) -> Result<(), LedgerError> {
        self.settle(approval, ApprovalState::Refused)
    }

    /// Redeem an approval by value. A granted approval yields exactly the one
    /// decision reserved for it and is retired; so is a refused one, yielding
    /// nothing. A pending one hands the handle back.
    pub fn redeem(&mut self, approval: ApprovalId) -> Result<Redemption, LedgerError> {
        self.check_epoch(approval.epoch())?;
        let a = approval.number();
        let state = match self.approvals.get(&a) {
            Some(r) => r.state,
            None => return Err(self.approval_error(a)),
        };
        match state {
            ApprovalState::Pending => Ok(Redemption::Pending(approval)),
            ApprovalState::Granted => match self.approvals.remove(&a) {
                Some(Reservation { decision, state: _ }) => {
                    self.live.insert(decision);
                    Ok(Redemption::Granted(DecisionId::mint(self.epoch, decision)))
                }
                None => Err(self.approval_error(a)),
            },
            ApprovalState::Refused => match self.approvals.remove(&a) {
                Some(_) => Ok(Redemption::Refused),
                None => Err(self.approval_error(a)),
            },
        }
    }

    /// Spend a decision id. By value: the caller's id is gone whatever the
    /// answer, and the ledger forgets a spent id so a copy decoded from the
    /// same bytes is [`LedgerError::Retired`].
    pub fn consume(&mut self, decision: DecisionId) -> Result<Spent, LedgerError> {
        self.check_epoch(decision.epoch())?;
        let n = decision.number();
        if self.live.remove(&n) {
            return Ok(Spent {
                epoch: self.epoch,
                decision: n,
            });
        }
        if self.approvals.values().any(|r| r.decision == n) {
            return Err(LedgerError::AwaitingApproval { decision: n });
        }
        if n < self.next_decision {
            Err(LedgerError::Retired { decision: n })
        } else {
            Err(LedgerError::NeverIssued { decision: n })
        }
    }
}
