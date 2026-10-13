//! The in-process register of verified decisions: what a pod holds, what it has spent, and what
//! has been superseded.
//!
//! Mirrors `nucleus-decision-protocol`'s `DecisionLedger`: the one place that retires a one-shot
//! right, by value (ADR 0007 C-4), with "spent" and "never held" as different refusals (A-8).
//! A copy of a spent decision re-verified from the same bytes has the same id, and the ledger
//! remembers that id, so it is refused as [`LedgerError::Spent`] rather than spent again.

use std::collections::{BTreeMap, BTreeSet};

use crate::{Action, Coverage, DecisionId, SignedDecision, Window};

/// Most decisions one ledger holds at once.
pub const MAX_HELD: usize = 256;
/// Most retired ids (spent plus superseded) one ledger remembers. Past it the ledger refuses
/// rather than forgets, because forgetting a spent id would let it be spent again.
pub const MAX_RETIRED: usize = 4096;

/// The record that a one-shot decision was used, for the action it covered.
///
/// Minted only by the ledger, after the decision left it.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a Spent is the record that the decision was used; carry it to the receipt"]
pub struct Spent {
    decision: DecisionId,
    capability: String,
    at: u64,
}

impl Spent {
    /// The decision spent.
    pub const fn decision(&self) -> DecisionId {
        self.decision
    }

    /// The capability it was spent on.
    pub fn capability(&self) -> &str {
        &self.capability
    }

    /// When, by the ledger's caller's clock.
    pub const fn at(&self) -> u64 {
        self.at
    }
}

/// Why the ledger refused. Each arm is a distinct event.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LedgerError {
    /// This one-shot decision was already spent in this ledger: a replay.
    #[error("decision {0} was already spent")]
    Spent(DecisionId),
    /// A later decision replaced this one.
    #[error("decision {id} is superseded by {by}")]
    Superseded {
        /// The refused decision.
        id: DecisionId,
        /// The one that replaced it.
        by: DecisionId,
    },
    /// No decision with this id is held.
    #[error("decision {0} is not held")]
    NotHeld(DecisionId),
    /// A standing decision is cited, not spent.
    #[error("decision {0} is standing; cite it instead of spending it")]
    Standing(DecisionId),
    /// A one-shot decision is spent, not cited: citing it would let it be used without limit.
    #[error("decision {0} is one-shot; spend it instead of citing it")]
    OneShot(DecisionId),
    /// `now` is before the window.
    #[error("decision {0} is not valid yet")]
    NotYetValid(DecisionId),
    /// `now` is after the window.
    #[error("decision {0} has expired")]
    Expired(DecisionId),
    /// The action is outside the signed scope.
    #[error("decision {0} does not cover this action")]
    OutOfScope(DecisionId),
    /// The ledger cannot tell whether the action is in scope, which is not "covered".
    #[error("decision {0} cannot be shown to cover this action")]
    CannotTell(DecisionId),
    /// A decision names, as superseded, a held decision for a different question.
    #[error("decision {id} supersedes {old}, which answers another question")]
    SupersedesAnotherQuestion {
        /// The superseding decision.
        id: DecisionId,
        /// The one it names.
        old: DecisionId,
    },
    /// The decision's `supersedes` is not a decision id ([`crate::verify`] refuses this first).
    #[error("decision {0} names a malformed superseded id")]
    BadSupersedes(DecisionId),
    /// The ledger is at [`MAX_HELD`] or [`MAX_RETIRED`].
    #[error("decision ledger is full")]
    Full,
}

/// The verified decisions one process holds.
#[derive(Debug)]
pub struct DecisionLedger {
    held: BTreeMap<DecisionId, SignedDecision>,
    /// Superseded id -> the id that replaced it.
    superseded: BTreeMap<DecisionId, DecisionId>,
    spent: BTreeSet<DecisionId>,
}

impl DecisionLedger {
    /// A ledger holding nothing.
    pub const fn empty() -> Self {
        Self {
            held: BTreeMap::new(),
            superseded: BTreeMap::new(),
            spent: BTreeSet::new(),
        }
    }

    fn retired(&self, id: DecisionId) -> Result<(), LedgerError> {
        if self.spent.contains(&id) {
            return Err(LedgerError::Spent(id));
        }
        if let Some(by) = self.superseded.get(&id) {
            return Err(LedgerError::Superseded { id, by: *by });
        }
        Ok(())
    }

    fn retired_count(&self) -> usize {
        self.spent.len().saturating_add(self.superseded.len())
    }

    /// Hold a verified decision. Holding one already held is a no-op that returns its id.
    ///
    /// A decision that supersedes another retires it: the held one is dropped, and either way
    /// its id is remembered, so a later attempt to hold or use it is refused.
    pub fn hold(&mut self, decision: SignedDecision) -> Result<DecisionId, LedgerError> {
        let id = decision.id();
        self.retired(id)?;
        if self.held.contains_key(&id) {
            return Ok(id);
        }
        if self.held.len() >= MAX_HELD {
            return Err(LedgerError::Full);
        }
        let old = match decision.record().supersedes.as_deref() {
            Some(hex) => {
                Some(DecisionId::from_hex(hex).map_err(|_| LedgerError::BadSupersedes(id))?)
            }
            None => None,
        };
        if let Some(old) = old {
            if let Some(prev) = self.held.get(&old) {
                let (p, d) = (prev.record(), decision.record());
                if p.tenant != d.tenant || p.question_id != d.question_id {
                    return Err(LedgerError::SupersedesAnotherQuestion { id, old });
                }
            }
            if !self.superseded.contains_key(&old) {
                if self.retired_count() >= MAX_RETIRED {
                    return Err(LedgerError::Full);
                }
                self.superseded.insert(old, id);
            }
            self.held.remove(&old);
        }
        self.held.insert(id, decision);
        Ok(id)
    }

    /// A held decision, if any. Holding it says nothing about `now`; use [`Self::cite`].
    pub fn get(&self, id: DecisionId) -> Option<&SignedDecision> {
        self.held.get(&id)
    }

    /// Every held decision, by id.
    pub fn iter(&self) -> impl Iterator<Item = &SignedDecision> {
        self.held.values()
    }

    /// How many decisions are held.
    pub fn len(&self) -> usize {
        self.held.len()
    }

    /// Whether none are.
    pub fn is_empty(&self) -> bool {
        self.held.is_empty()
    }

    fn usable(d: &SignedDecision, action: &Action<'_>, now: u64) -> Result<(), LedgerError> {
        let id = d.id();
        match d.window(now) {
            Window::Live => {}
            Window::NotYetValid => return Err(LedgerError::NotYetValid(id)),
            Window::Expired => return Err(LedgerError::Expired(id)),
        }
        match d.covers_action(action) {
            Coverage::Covered => Ok(()),
            Coverage::OutOfScope => Err(LedgerError::OutOfScope(id)),
            Coverage::CannotTell => Err(LedgerError::CannotTell(id)),
        }
    }

    /// Cite a held STANDING decision for an action: re-checks the window and the scope on every
    /// use. A one-shot decision is refused here, since a citation does not use it up.
    pub fn cite(
        &self,
        id: DecisionId,
        action: &Action<'_>,
        now: u64,
    ) -> Result<&SignedDecision, LedgerError> {
        self.retired(id)?;
        let d = self.held.get(&id).ok_or(LedgerError::NotHeld(id))?;
        if d.record().single_use {
            return Err(LedgerError::OneShot(id));
        }
        Self::usable(d, action, now)?;
        Ok(d)
    }

    /// Spend a held ONE-SHOT decision on an action. A refusal leaves it held; a success removes
    /// it and remembers its id, so a second spend, or a re-verified copy, is [`LedgerError::Spent`].
    pub fn spend(
        &mut self,
        id: DecisionId,
        action: &Action<'_>,
        now: u64,
    ) -> Result<Spent, LedgerError> {
        self.retired(id)?;
        let d = self.held.get(&id).ok_or(LedgerError::NotHeld(id))?;
        if !d.record().single_use {
            return Err(LedgerError::Standing(id));
        }
        Self::usable(d, action, now)?;
        let d = self.held.remove(&id).ok_or(LedgerError::NotHeld(id))?;
        self.retire_spent(d, action, now)
    }

    /// Spend a one-shot decision that was never held, by value: the caller's decision is gone
    /// whatever the answer.
    pub fn consume(
        &mut self,
        decision: SignedDecision,
        action: &Action<'_>,
        now: u64,
    ) -> Result<Spent, LedgerError> {
        let id = decision.id();
        self.retired(id)?;
        if !decision.record().single_use {
            return Err(LedgerError::Standing(id));
        }
        Self::usable(&decision, action, now)?;
        self.held.remove(&id);
        self.retire_spent(decision, action, now)
    }

    fn retire_spent(
        &mut self,
        decision: SignedDecision,
        action: &Action<'_>,
        now: u64,
    ) -> Result<Spent, LedgerError> {
        let id = decision.id();
        if self.retired_count() >= MAX_RETIRED {
            // Put nothing back: a decision that cannot be recorded as spent must not be usable.
            return Err(LedgerError::Full);
        }
        self.spent.insert(id);
        drop(decision);
        Ok(Spent {
            decision: id,
            capability: action.capability.to_string(),
            at: now,
        })
    }
}
