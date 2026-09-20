//! Making bids contemporaneous, and making them cost something.
//!
//! [`crate::clearing`] prices a round that already exists. On a live request
//! path there is no round: requests arrive one at a time, and a "second price"
//! computed over a single bid is zero forever. So something has to hold a
//! request briefly, collect whatever else arrives in that window, and clear the
//! group. That is this module.
//!
//! # Two properties, and they pull against each other
//!
//! **Deny on timeout.** A round that cannot clear must not fall open. Every path
//! out of [`RoundScheduler::join`] that is not a cleared outcome is a
//! [`Verdict::Denied`] — a dropped closer task, a panicking charger, a window
//! that elapsed with the round somehow still open. The failure mode this
//! forbids is the one the repository keeps rediscovering in shell: a
//! precondition that fails quietly and reports the dependent decision as a pass.
//!
//! **A charge that fails denies the slot.** The winner of a round it cannot pay
//! for does not get the slot (`Verdict::Denied(DenyReason::ChargeRefused)`).
//! This is the point of the whole exercise: truthfulness is a claim about a
//! bidder's *utility*, and a bid that costs nothing to inflate has none. If the
//! charge were best-effort, `vickrey_truthful` would be decoration.
//!
//! # What the window costs
//!
//! Latency, on every request that uses it. A 50 ms window adds up to 50 ms to a
//! mediated call, which is why the live path enables this per dimension rather
//! than globally: it is worth paying where a slot is genuinely contended and
//! pure overhead where it is not.
//!
//! # Cancellation
//!
//! The round is closed by a detached task rather than by the first bidder's
//! future, so a client that disconnects mid-window cannot strand everyone else
//! in the round. That task outlives a listener shutdown by at most one window —
//! the same shape as the spawned-connection-task issue in `vsock_bridge`, and
//! bounded here by construction rather than by hope.
//!
//! # A-19
//!
//! The grouping is the property, so it was driven red before being trusted:
//! making `join` open a fresh round for every bid — the "batching silently does
//! not batch" defect, which leaves each bidder alone at a second price of zero —
//! fails `concurrent_bidders_land_in_one_round_and_pay_a_second_price` and
//! `a_winner_that_cannot_pay_is_denied`. `a_lone_bidder_clears_uncontested_at_zero`
//! and `an_unwired_charger_grants_nothing` stay green under that defect, which
//! is why neither of them is the test this module relies on.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nucleus_econ_types::{AgentId, AuctionId, MicroUsd};
use nucleus_permission_market::PermissionDimension;
use nucleus_recompute::ClearingReceipt;
use tokio::sync::oneshot;

use crate::bid::SignedBid;
use crate::clearing::{Clearing, VcgClearing};
use crate::round::{Round, RoundOutcome};

/// What a bidder learns when its round closes.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// The slot is yours, at `price`, and the charge went through.
    Won {
        /// The Clarke pivot, already charged.
        price: MicroUsd,
        /// The receipt for the round that produced it.
        receipt: Arc<ClearingReceipt>,
    },
    /// Someone outbid you. You are charged nothing.
    Lost,
    /// No slot, for a reason that is not "you were outbid".
    Denied(DenyReason),
}

/// Why a bidder got nothing, when it was not simply outbid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DenyReason {
    /// The round did not close within its window. Fail-closed: a scheduler that
    /// stalls must not become a scheduler that grants.
    #[error("the round did not clear within its window")]
    RoundDidNotClear,
    /// The winner could not be charged, so it does not get the slot.
    #[error("the winning bid could not be charged")]
    ChargeRefused,
    /// The mechanism rejected the round's declared inputs.
    #[error("the round could not be cleared")]
    ClearFailed,
}

/// Why a charge did not go through.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChargeError {
    /// The payer's remaining budget does not cover the price.
    #[error("insufficient budget: {available} µUSD available, {price} µUSD owed")]
    InsufficientBudget {
        /// What the payer had.
        available: u64,
        /// What the slot cost.
        price: u64,
    },
    /// The ledger refused for a reason of its own.
    #[error("the ledger refused the charge: {0}")]
    Ledger(String),
}

/// Where a cleared price is actually debited.
///
/// A seam rather than a direct `portcullis::BudgetLedger` dependency, because
/// the property this module must hold — *a winner that cannot pay does not get
/// the slot* — is testable only if the failure is injectable.
pub trait Charger: Send + Sync + 'static {
    /// Debit `price` from `payer`.
    ///
    /// # Errors
    ///
    /// [`ChargeError`] if the payer cannot cover it, which denies the slot.
    fn charge(&self, payer: &AgentId, price: MicroUsd) -> Result<(), ChargeError>;
}

/// So a caller that picks its charger at runtime can still name one type.
impl Charger for Box<dyn Charger> {
    fn charge(&self, payer: &AgentId, price: MicroUsd) -> Result<(), ChargeError> {
        (**self).charge(payer, price)
    }
}

/// A charger that refuses everything. The honest default for a deployment that
/// has enabled clearing but not wired a ledger: every round clears, every winner
/// is denied, and nobody is quietly granted a slot for free.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnwiredCharger;

impl Charger for UnwiredCharger {
    fn charge(&self, _payer: &AgentId, price: MicroUsd) -> Result<(), ChargeError> {
        Err(ChargeError::Ledger(format!(
            "no budget ledger is wired; refusing to grant a slot priced at {} µUSD for free",
            price.get()
        )))
    }
}

/// Charges a cleared price against `portcullis`'s budget ledger — the real one,
/// whose conservation law (`Σ live child allocations + consumed ≤ max`) is Kani-proven
/// over the shipped type by `proof_budget_ledger_conserves`.
///
/// A charge is an allocate-then-release pair rather than a bespoke "debit"
/// path: `release` folds what was actually spent into `consumed` and refunds
/// the rest, so charging the full allocation is a permanent debit *expressed in
/// the operations the proof is about*. A second debit path would be a second
/// decider for the same fact (G-1), and the one that is not proven would be the
/// one that drifts.
#[cfg(feature = "certificate")]
#[derive(Debug)]
pub struct LedgerCharger {
    ledger: Mutex<portcullis::budget_ledger::BudgetLedger>,
    seq: std::sync::atomic::AtomicU64,
}

#[cfg(feature = "certificate")]
impl LedgerCharger {
    /// Charge against `ledger`.
    #[must_use]
    pub fn new(ledger: portcullis::budget_ledger::BudgetLedger) -> Self {
        LedgerCharger {
            ledger: Mutex::new(ledger),
            seq: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// What the ledger has left, in micro-USD, for reporting a refusal.
    fn available_micro(ledger: &portcullis::budget_ledger::BudgetLedger) -> u64 {
        use rust_decimal::prelude::ToPrimitive;
        (ledger.available() * rust_decimal::Decimal::from(1_000_000u32))
            .trunc()
            .to_u64()
            .unwrap_or(0)
    }
}

#[cfg(feature = "certificate")]
impl Charger for LedgerCharger {
    fn charge(&self, _payer: &AgentId, price: MicroUsd) -> Result<(), ChargeError> {
        // Micro-USD is exactly a `Decimal` of scale 6, so this round-trip loses
        // nothing — which matters because the ledger rounds a charge UP
        // (`usd_to_micro_ceil`), and an inexact conversion would charge a
        // micro-dollar more than the mechanism cleared.
        let usd = rust_decimal::Decimal::from_i128_with_scale(i128::from(price.get()), 6);
        let id = u128::from(
            self.seq
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                .wrapping_add(1),
        );
        let mut ledger = self.ledger.lock().unwrap_or_else(|e| e.into_inner());
        ledger.try_allocate(id, usd).map_err(|e| match e {
            portcullis::budget_ledger::BudgetError::Ledger(
                portcullis::budget_ledger::LedgerError::InsufficientBudget { .. },
            ) => ChargeError::InsufficientBudget {
                available: Self::available_micro(&ledger),
                price: price.get(),
            },
            other => ChargeError::Ledger(other.to_string()),
        })?;
        // Spend the whole allocation: the price is owed, not reserved.
        ledger
            .release(id, usd)
            .map(|_refund| ())
            .map_err(|e| ChargeError::Ledger(e.to_string()))
    }
}

struct OpenRound {
    round: Round,
    waiters: Vec<(AgentId, oneshot::Sender<Verdict>)>,
}

/// Collects bids into time-boxed rounds and clears them.
pub struct RoundScheduler<C: Charger> {
    window: Duration,
    charger: C,
    open: Mutex<HashMap<PermissionDimension, OpenRound>>,
    seq: Mutex<u64>,
}

impl<C: Charger> RoundScheduler<C> {
    /// A scheduler whose rounds collect for `window` before clearing.
    pub fn new(window: Duration, charger: C) -> Arc<Self> {
        Arc::new(RoundScheduler {
            window,
            charger,
            open: Mutex::new(HashMap::new()),
            seq: Mutex::new(0),
        })
    }

    /// Submit a bid and wait for the round's verdict.
    ///
    /// Returns [`Verdict::Denied`] rather than an error for every non-clearing
    /// path, so a caller cannot accidentally treat a failure as a grant by
    /// ignoring an error type.
    pub async fn join(self: &Arc<Self>, bid: SignedBid) -> Verdict {
        let dimension = bid.dimension();
        let bidder = bid.bidder().clone();
        let (tx, rx) = oneshot::channel();

        let opened = {
            // The lock is never held across an await: everything inside this
            // block is synchronous map work.
            let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
            let fresh = !open.contains_key(&dimension);
            if fresh {
                let mut seq = self.seq.lock().unwrap_or_else(|e| e.into_inner());
                *seq = seq.wrapping_add(1);
                let id = AuctionId::new(format!("{dimension:?}-{seq}"));
                open.insert(
                    dimension,
                    OpenRound {
                        round: Round::open(id, dimension),
                        waiters: Vec::new(),
                    },
                );
            }
            let entry = open
                .get_mut(&dimension)
                .expect("just inserted or already present");
            match entry.round.submit(bid) {
                Ok(()) => entry.waiters.push((bidder, tx)),
                // A bid the round will not admit (wrong dimension is
                // impossible here; a duplicate bidder is not) never joins, and
                // is denied rather than silently dropped.
                Err(_) => return Verdict::Denied(DenyReason::ClearFailed),
            }
            fresh
        };

        if opened {
            let me = Arc::clone(self);
            let window = self.window;
            // Detached on purpose — see the module docs on cancellation.
            tokio::spawn(async move {
                tokio::time::sleep(window).await;
                me.close(dimension);
            });
        }

        // The window is the contract; twice it is the margin for the closer
        // task being scheduled late. Past that, fail closed.
        match tokio::time::timeout(self.window.saturating_mul(2) + Duration::from_secs(1), rx).await
        {
            Ok(Ok(v)) => v,
            // Closer dropped the sender, or the deadline passed with no verdict.
            Ok(Err(_)) | Err(_) => Verdict::Denied(DenyReason::RoundDidNotClear),
        }
    }

    /// Close the open round for `dimension`, clear it, charge the winner, and
    /// dispatch a verdict to every waiter.
    fn close(&self, dimension: PermissionDimension) {
        let Some(entry) = self
            .open
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&dimension)
        else {
            return; // already closed
        };
        let OpenRound { round, waiters } = entry;

        let outcome = match VcgClearing.clear(&round) {
            Ok(o) => o,
            Err(_) => {
                for (_, tx) in waiters {
                    let _ = tx.send(Verdict::Denied(DenyReason::ClearFailed));
                }
                return;
            }
        };

        let (winner, price, receipt) = match &outcome {
            RoundOutcome::Cleared {
                winner,
                price,
                receipt,
            } => (winner.clone(), *price, Arc::new((**receipt).clone())),
            RoundOutcome::Uncontested { winner, receipt } => (
                winner.clone(),
                MicroUsd::ZERO,
                Arc::new((**receipt).clone()),
            ),
            // `PostedPrice` cannot arise: this scheduler clears with
            // `VcgClearing`. `NoBids` cannot either, since a waiter exists only
            // because its bid was admitted.
            RoundOutcome::PostedPrice { .. } | RoundOutcome::NoBids => {
                for (_, tx) in waiters {
                    let _ = tx.send(Verdict::Denied(DenyReason::ClearFailed));
                }
                return;
            }
        };

        // The charge decides whether the winner actually gets the slot. A
        // refusal denies it rather than granting on credit.
        let charged = self.charger.charge(&winner, price);

        for (agent, tx) in waiters {
            let verdict = if agent == winner {
                match &charged {
                    Ok(()) => Verdict::Won {
                        price,
                        receipt: Arc::clone(&receipt),
                    },
                    Err(_) => Verdict::Denied(DenyReason::ChargeRefused),
                }
            } else {
                Verdict::Lost
            };
            let _ = tx.send(verdict);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::bid;
    use std::sync::atomic::{AtomicU64, Ordering};

    const EGRESS: PermissionDimension = PermissionDimension::NetworkEgress;
    const WINDOW: Duration = Duration::from_millis(40);

    /// Records what it was asked to charge, and always succeeds.
    #[derive(Debug, Default)]
    struct Recording {
        total: AtomicU64,
        calls: AtomicU64,
    }

    impl Charger for Arc<Recording> {
        fn charge(&self, _payer: &AgentId, price: MicroUsd) -> Result<(), ChargeError> {
            self.total.fetch_add(price.get(), Ordering::SeqCst);
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Refuses everything.
    #[derive(Debug, Default, Clone, Copy)]
    struct Broke;

    impl Charger for Broke {
        fn charge(&self, _payer: &AgentId, price: MicroUsd) -> Result<(), ChargeError> {
            Err(ChargeError::InsufficientBudget {
                available: 0,
                price: price.get(),
            })
        }
    }

    /// NON-VACUITY, and the reason this module exists: two bidders that arrive
    /// separately must end up in the SAME round. If they did not, each would
    /// clear alone at a second price of zero and the scheduler would be an
    /// expensive way to grant everything for free.
    #[tokio::test]
    async fn concurrent_bidders_land_in_one_round_and_pay_a_second_price() {
        let rec = Arc::new(Recording::default());
        let s = RoundScheduler::new(WINDOW, Arc::clone(&rec));

        let a = {
            let s = Arc::clone(&s);
            tokio::spawn(async move { s.join(bid("a", 100, EGRESS)).await })
        };
        let b = {
            let s = Arc::clone(&s);
            tokio::spawn(async move { s.join(bid("b", 70, EGRESS)).await })
        };

        let (va, vb) = (a.await.unwrap(), b.await.unwrap());
        assert!(
            matches!(va, Verdict::Won { price, .. } if price == MicroUsd::new(70)),
            "a should win at b's bid: {va:?}"
        );
        assert!(matches!(vb, Verdict::Lost), "b should lose: {vb:?}");
        assert_eq!(
            rec.calls.load(Ordering::SeqCst),
            1,
            "one winner, one charge"
        );
        assert_eq!(rec.total.load(Ordering::SeqCst), 70);
    }

    /// The whole point of charging: the loser pays nothing, so a losing bid is
    /// free and an inflated one is not.
    #[tokio::test]
    async fn a_loser_is_never_charged() {
        let rec = Arc::new(Recording::default());
        let s = RoundScheduler::new(WINDOW, Arc::clone(&rec));
        let a = {
            let s = Arc::clone(&s);
            tokio::spawn(async move { s.join(bid("a", 10, EGRESS)).await })
        };
        let b = {
            let s = Arc::clone(&s);
            tokio::spawn(async move { s.join(bid("b", 20, EGRESS)).await })
        };
        let _ = (a.await.unwrap(), b.await.unwrap());
        assert_eq!(rec.calls.load(Ordering::SeqCst), 1);
    }

    /// A winner that cannot pay is denied, not granted on credit.
    #[tokio::test]
    async fn a_winner_that_cannot_pay_is_denied() {
        let s = RoundScheduler::new(WINDOW, Broke);
        let a = {
            let s = Arc::clone(&s);
            tokio::spawn(async move { s.join(bid("a", 100, EGRESS)).await })
        };
        let b = {
            let s = Arc::clone(&s);
            tokio::spawn(async move { s.join(bid("b", 70, EGRESS)).await })
        };
        let (va, vb) = (a.await.unwrap(), b.await.unwrap());
        assert!(
            matches!(va, Verdict::Denied(DenyReason::ChargeRefused)),
            "{va:?}"
        );
        assert!(
            matches!(vb, Verdict::Lost),
            "the loser is unaffected: {vb:?}"
        );
    }

    /// With no ledger wired, nobody gets a slot. The default must not be "free".
    #[tokio::test]
    async fn an_unwired_charger_grants_nothing() {
        let s = RoundScheduler::new(WINDOW, UnwiredCharger);
        let v = s.join(bid("a", 100, EGRESS)).await;
        assert!(
            matches!(v, Verdict::Denied(DenyReason::ChargeRefused)),
            "{v:?}"
        );
    }

    /// A single bidder still clears — at zero, and reported as such — rather
    /// than hanging until the deadline.
    #[tokio::test]
    async fn a_lone_bidder_clears_uncontested_at_zero() {
        let rec = Arc::new(Recording::default());
        let s = RoundScheduler::new(WINDOW, Arc::clone(&rec));
        let v = s.join(bid("a", 100, EGRESS)).await;
        assert!(
            matches!(v, Verdict::Won { price, .. } if price == MicroUsd::ZERO),
            "{v:?}"
        );
    }

    /// Different scarce goods do not compete with each other.
    #[tokio::test]
    async fn rounds_are_per_dimension() {
        let rec = Arc::new(Recording::default());
        let s = RoundScheduler::new(WINDOW, Arc::clone(&rec));
        let a = {
            let s = Arc::clone(&s);
            tokio::spawn(async move { s.join(bid("a", 100, EGRESS)).await })
        };
        let b = {
            let s = Arc::clone(&s);
            tokio::spawn(
                async move { s.join(bid("b", 70, PermissionDimension::CommandExec)).await },
            )
        };
        let (va, vb) = (a.await.unwrap(), b.await.unwrap());
        // Each is alone in its own round, so each wins uncontested at zero.
        assert!(matches!(va, Verdict::Won { .. }), "{va:?}");
        assert!(matches!(vb, Verdict::Won { .. }), "{vb:?}");
        assert_eq!(rec.calls.load(Ordering::SeqCst), 2, "two rounds, two wins");
    }

    /// The real ledger, charged for real: a price within budget goes through and
    /// permanently reduces what is available, so a second charge sees less.
    #[cfg(feature = "certificate")]
    #[test]
    fn the_ledger_charger_debits_and_the_debit_persists() {
        use portcullis::budget_ledger::BudgetLedger;
        use rust_decimal::Decimal;

        let budget = portcullis::BudgetLattice {
            max_cost_usd: Decimal::from_i128_with_scale(1_000_000, 6), // $1.00
            consumed_usd: Decimal::ZERO,
            ..Default::default()
        };
        let c = LedgerCharger::new(BudgetLedger::for_parent(&budget));
        let who = AgentId::new("a");

        c.charge(&who, MicroUsd::new(400_000)).expect("within $1");
        {
            let l = c.ledger.lock().unwrap();
            assert_eq!(
                LedgerCharger::available_micro(&l),
                600_000,
                "debit persists"
            );
        }
        c.charge(&who, MicroUsd::new(600_000))
            .expect("exactly the rest");
        {
            let l = c.ledger.lock().unwrap();
            assert_eq!(LedgerCharger::available_micro(&l), 0);
        }
    }

    /// Over budget is refused, with the numbers a caller needs to say why.
    #[cfg(feature = "certificate")]
    #[test]
    fn the_ledger_charger_refuses_what_the_budget_cannot_cover() {
        use portcullis::budget_ledger::BudgetLedger;
        use rust_decimal::Decimal;

        let budget = portcullis::BudgetLattice {
            max_cost_usd: Decimal::from_i128_with_scale(10, 6), // 10 µUSD
            consumed_usd: Decimal::ZERO,
            ..Default::default()
        };
        let c = LedgerCharger::new(BudgetLedger::for_parent(&budget));
        let err = c
            .charge(&AgentId::new("a"), MicroUsd::new(11))
            .expect_err("over budget");
        assert_eq!(
            err,
            ChargeError::InsufficientBudget {
                available: 10,
                price: 11
            }
        );
    }

    /// FAIL CLOSED. If the closer never runs, the waiter is denied rather than
    /// left to a caller that might read "no error" as "granted". Simulated by
    /// closing nothing: the bid is registered directly, bypassing `join`'s
    /// spawn, so no task will ever close this round.
    #[tokio::test]
    async fn a_round_that_never_closes_denies_rather_than_grants() {
        let s = RoundScheduler::new(Duration::from_millis(10), UnwiredCharger);
        let (tx, rx) = oneshot::channel();
        {
            let mut open = s.open.lock().unwrap();
            let mut round = Round::open(AuctionId::new("stuck"), EGRESS);
            round.submit(bid("a", 100, EGRESS)).unwrap();
            open.insert(
                EGRESS,
                OpenRound {
                    round,
                    waiters: vec![(AgentId::new("a"), tx)],
                },
            );
        }
        let v = match tokio::time::timeout(Duration::from_millis(60), rx).await {
            Ok(Ok(v)) => v,
            Ok(Err(_)) | Err(_) => Verdict::Denied(DenyReason::RoundDidNotClear),
        };
        assert!(
            matches!(v, Verdict::Denied(DenyReason::RoundDidNotClear)),
            "{v:?}"
        );
    }
}
