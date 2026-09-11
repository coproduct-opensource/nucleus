//! Atomic budget enforcement.
//!
//! `portcullis::BudgetLattice` charges through `&mut self`. This is the
//! shared-state face: many threads hold one `AtomicBudget` and none of them
//! can race the others into an overspend.
//!
//! # Why this is a `LedgerCore` and not three counters
//!
//! It used to be three hand-rolled `(max: u64, consumed: AtomicU64)` pairs
//! with a compare-and-swap loop each. Two things were wrong with that, and
//! both are the shape ADR 0006 is about — a mechanism that is written
//! correctly next door and not used here.
//!
//! **The constructor did not clamp.** `BudgetLattice::consumed_usd` can
//! exceed `max_cost_usd` — `BudgetLedger::for_parent` handles exactly that
//! case, and says so — but this type copied both across unchecked. Then
//! `remaining_usd()` computed `max - consumed`, which for an overspent parent
//! is a `u64` underflow: a panic under `debug_assertions` and, without them,
//! roughly 1.8e13 USD of budget that does not exist. The same subtraction sat
//! in the `BudgetExhausted` arm of the charge path.
//!
//! [`LedgerCore::new`] establishes `consumed ≤ max` at construction and every
//! method preserves it, so the clamp is not something a future edit has to
//! remember. Its `available_units` is saturating by construction.
//!
//! **Reservation was by amount, not by identity.** `reserve` handed back a
//! detached child budget and `release` took an `f64`, so nothing connected
//! the two: the pairing was maintained by a test that grepped the caller's own
//! source for `.release(reserved_usd)` appearing at least twice.
//! [`Reservation`] is `#[must_use]` and carries the ledger slot's identity, so
//! a reservation that is neither committed nor released is a compiler
//! diagnostic rather than a convention.
//!
//! # What was deleted
//!
//! The input- and output-token axes. They were set from the policy at
//! construction and never touched again: `charge_input_tokens` and
//! `charge_output_tokens` had no callers outside this file's own tests, the
//! policy's `consumed_input_tokens` / `consumed_output_tokens` were dropped on
//! the floor by the constructor, and `reserve` handed each child
//! `max_input_tokens / 2` — under a comment reading "give half of remaining",
//! against a ceiling that is never decremented — on an object the one
//! production caller discards. Nothing in the tree counts tokens, so wiring
//! them would have meant inventing the policy for who does.

use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{NucleusError, Result};
use portcullis::{BudgetLattice, ChildId, LedgerCore, LedgerError, MicroUsd};

/// Live reservations one budget can hold at once.
///
/// A reservation occupies a slot only between `reserve` and its commit or
/// release — the window in which a sub-pod is being created — so this bounds
/// concurrent in-flight creations, not sub-pods ever created.
pub const BUDGET_SLOTS: usize = 32;

/// Thread-safe budget enforcement.
///
/// Wraps a `BudgetLattice` policy and charges against it in a way concurrent
/// access cannot bypass.
pub struct AtomicBudget {
    /// One lock, not one per axis. [`LedgerCore`] needs `&mut`, and taking the
    /// lock once also makes the ceiling check and the charge a single critical
    /// section — which three independent compare-and-swap loops never were.
    ledger: Mutex<LedgerCore<MicroUsd, BUDGET_SLOTS>>,
    /// Source of slot identities. Monotone and never reused within a process,
    /// so a released slot's id cannot be mistaken for a live one.
    next_child: AtomicU64,
}

/// A parent's budget set aside for a child that does not exist yet.
///
/// Hold it until the child is real, then [`AtomicBudget::commit`] it; hand it
/// back with [`AtomicBudget::release`] if the child is refused. It is
/// deliberately not `Clone`: one reservation, one outcome.
#[must_use = "a reservation must be committed or released; dropping it strands \
              the parent's budget in a slot until the process exits"]
#[derive(Debug, PartialEq, Eq)]
pub struct Reservation {
    child: ChildId,
}

/// Whole micro-dollars for a non-negative, finite USD amount. The ONE place
/// the f64→u64 conversion lives (the clippy cast ratchet counts each `as`);
/// callers validate sign and finiteness first.
fn usd_to_micro(usd: f64) -> MicroUsd {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    {
        (usd * 1_000_000.0) as MicroUsd
    }
}

/// USD for a micro-USD quantity, for reporting only.
fn micro_to_usd(micro: MicroUsd) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    {
        micro as f64 / 1_000_000.0
    }
}

/// Reject an amount that cannot be a charge before it reaches the ledger.
fn validated_micro(amount: f64) -> Result<MicroUsd> {
    if amount.is_nan() || amount.is_infinite() {
        return Err(NucleusError::InvalidCharge {
            reason: "amount is NaN or infinite".into(),
        });
    }
    if amount <= 0.0 {
        return Err(NucleusError::InvalidCharge {
            reason: "amount must be positive".into(),
        });
    }
    Ok(usd_to_micro(amount))
}

impl AtomicBudget {
    /// Create a budget from a policy.
    ///
    /// A policy whose `consumed_usd` exceeds `max_cost_usd` is clamped by
    /// [`LedgerCore::new`], so an overspent parent starts with nothing left
    /// rather than with an underflowed remainder.
    pub fn new(policy: &BudgetLattice) -> Self {
        let max = policy
            .max_cost_usd
            .to_string()
            .parse::<f64>()
            .unwrap_or(0.0);
        let consumed = policy
            .consumed_usd
            .to_string()
            .parse::<f64>()
            .unwrap_or(0.0);
        Self {
            ledger: Mutex::new(LedgerCore::new(
                usd_to_micro(max.max(0.0)),
                usd_to_micro(consumed.max(0.0)),
            )),
            next_child: AtomicU64::new(1),
        }
    }

    /// Charge an amount in USD.
    ///
    /// Fails if the charge would exceed what is left, or if the amount is
    /// negative, zero, NaN or infinite. Atomic: concurrent calls do not race.
    pub fn charge_usd(&self, amount: f64) -> Result<()> {
        self.charge_micro_usd(validated_micro(amount)?)
    }

    /// Charge an amount in micro-dollars.
    fn charge_micro_usd(&self, amount_micro: MicroUsd) -> Result<()> {
        let mut ledger = self.ledger.lock();
        let available = ledger.available_units();
        if amount_micro > available {
            return Err(NucleusError::BudgetExhausted {
                requested: micro_to_usd(amount_micro),
                remaining: micro_to_usd(available),
            });
        }
        // Checked above, so this records rather than clamps. `available` is
        // saturating, so the old `max - consumed` underflow is unreachable.
        ledger.record_parent_consumed(amount_micro);
        Ok(())
    }

    /// USD still available to charge or reserve.
    pub fn remaining_usd(&self) -> f64 {
        micro_to_usd(self.ledger.lock().available_units())
    }

    /// USD no longer available: spent, plus set aside in live reservations.
    ///
    /// Reservations are counted deliberately. Before the ledger, `reserve`
    /// charged the parent immediately, so an in-flight reservation showed up
    /// here — and `pod_mgmt::create_sub_pod` folds this number into the
    /// delegation ceiling it narrows a child against. Reporting only
    /// `parent_consumed_units()` would quietly widen that ceiling while a
    /// concurrent sub-pod creation was in flight. `consumed + remaining` is
    /// the parent's max, at every instant.
    pub fn consumed_usd(&self) -> f64 {
        let ledger = self.ledger.lock();
        micro_to_usd(
            ledger
                .parent_max_units()
                .saturating_sub(ledger.available_units()),
        )
    }

    /// Is there anything left to spend?
    pub fn has_remaining(&self) -> bool {
        self.ledger.lock().available_units() > 0
    }

    /// Set aside budget for a child that does not exist yet.
    ///
    /// The amount leaves the parent's available budget immediately, so a
    /// parent cannot hand the same budget to two children — the defect the
    /// ledger exists to make unrepresentable. Commit or release the result.
    pub fn reserve(&self, amount_usd: f64) -> Result<Reservation> {
        let micro = validated_micro(amount_usd)?;
        let child = ChildId::from(self.next_child.fetch_add(1, Ordering::Relaxed));
        let mut ledger = self.ledger.lock();
        match ledger.try_allocate(child, micro) {
            Ok(()) => Ok(Reservation { child }),
            Err(LedgerError::InsufficientBudget {
                requested,
                available,
            }) => Err(NucleusError::BudgetExhausted {
                requested: micro_to_usd(requested),
                remaining: micro_to_usd(available),
            }),
            Err(e) => Err(NucleusError::InvalidCharge {
                reason: e.to_string(),
            }),
        }
    }

    /// Spend a reservation: the child became real, so its budget becomes the
    /// parent's consumption and the slot is freed.
    pub fn commit(&self, reservation: Reservation) {
        let mut ledger = self.ledger.lock();
        if let Some(amount) = ledger.allocation_of(reservation.child) {
            // Release reporting the full allocation as spent: the ledger folds
            // it into `parent_consumed` and refunds nothing.
            let _ = ledger.release(reservation.child, amount);
        }
    }

    /// Hand a reservation back: the child was refused, so nothing was spent.
    ///
    /// Cannot grant budget. The most it can do is undo its own reservation —
    /// `release` with zero consumption refunds exactly what was allocated.
    pub fn release(&self, reservation: Reservation) {
        let mut ledger = self.ledger.lock();
        let _ = ledger.release(reservation.child, 0);
    }

    /// Live reservations, for tests and diagnostics.
    #[doc(hidden)]
    pub fn live_reservations(&self) -> usize {
        self.ledger.lock().live_children()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal::Decimal;
    use std::sync::Arc;
    use std::thread;

    fn test_policy(max_usd: f64) -> BudgetLattice {
        BudgetLattice {
            max_cost_usd: Decimal::try_from(max_usd).unwrap(),
            consumed_usd: Decimal::ZERO,
            max_input_tokens: 100_000,
            max_output_tokens: 10_000,
            consumed_input_tokens: 0,
            consumed_output_tokens: 0,
        }
    }

    #[test]
    fn test_basic_charge() {
        let budget = AtomicBudget::new(&test_policy(10.0));

        assert!(budget.charge_usd(5.0).is_ok());
        assert!((budget.consumed_usd() - 5.0).abs() < 0.001);
        assert!((budget.remaining_usd() - 5.0).abs() < 0.001);
    }

    #[test]
    fn test_exceeds_budget() {
        let budget = AtomicBudget::new(&test_policy(10.0));

        assert!(budget.charge_usd(5.0).is_ok());
        assert!(budget.charge_usd(6.0).is_err()); // Would exceed
        assert!((budget.consumed_usd() - 5.0).abs() < 0.001); // Unchanged
    }

    #[test]
    fn test_invalid_amounts() {
        let budget = AtomicBudget::new(&test_policy(10.0));

        assert!(budget.charge_usd(-1.0).is_err());
        assert!(budget.charge_usd(0.0).is_err());
        assert!(budget.charge_usd(f64::NAN).is_err());
        assert!(budget.charge_usd(f64::INFINITY).is_err());
    }

    #[test]
    fn test_concurrent_charges() {
        let budget = Arc::new(AtomicBudget::new(&test_policy(10.0)));
        let mut handles = vec![];

        // Spawn 100 threads each trying to charge $0.20
        for _ in 0..100 {
            let budget = Arc::clone(&budget);
            handles.push(thread::spawn(move || budget.charge_usd(0.20)));
        }

        let mut success_count = 0;
        for handle in handles {
            if handle.join().unwrap().is_ok() {
                success_count += 1;
            }
        }

        // Exactly 50 should succeed ($10 / $0.20 = 50)
        assert_eq!(success_count, 50);
        assert!((budget.consumed_usd() - 10.0).abs() < 0.001);
    }

    #[test]
    fn test_reservation() {
        let parent = AtomicBudget::new(&test_policy(10.0));

        // The reservation leaves the parent's available budget at once.
        let r = parent.reserve(3.0).unwrap();
        assert!((parent.remaining_usd() - 7.0).abs() < 0.001);
        assert_eq!(parent.live_reservations(), 1);
        // A live reservation counts as spend: it is promised, so it is not
        // available, and `consumed + remaining` is the parent's max at every
        // instant. See `a_live_reservation_counts_as_spend_for_ceiling_narrowing`.
        assert!((parent.consumed_usd() - 3.0).abs() < 0.001);

        parent.commit(r);
        assert_eq!(parent.live_reservations(), 0);
        assert!((parent.consumed_usd() - 3.0).abs() < 0.001);
        assert!((parent.remaining_usd() - 7.0).abs() < 0.001);
    }

    #[test]
    fn a_released_reservation_comes_back_whole() {
        let parent = AtomicBudget::new(&test_policy(10.0));
        let r = parent.reserve(4.0).unwrap();
        assert!((parent.remaining_usd() - 6.0).abs() < 0.001);

        parent.release(r);
        assert_eq!(parent.live_reservations(), 0);
        assert!((parent.remaining_usd() - 10.0).abs() < 0.001);
        assert!(parent.consumed_usd().abs() < 0.001);
    }

    // ── Regressions ──────────────────────────────────────────────────────

    /// `AtomicBudget::new` copied `consumed_usd` across without clamping it to
    /// `max_cost_usd`, and `remaining_usd()` was `max - consumed`. For an
    /// overspent parent that is a `u64` underflow: this test panicked with
    /// "attempt to subtract with overflow" under `debug_assertions`, and
    /// without them reported about 1.8e13 USD of budget that does not exist.
    /// `BudgetLedger::for_parent` had always handled this case; this type did
    /// not, which is the whole reason it now shares the ledger.
    #[test]
    fn an_overspent_parent_has_nothing_left_rather_than_an_underflow() {
        let mut policy = test_policy(1.0);
        policy.consumed_usd = Decimal::try_from(3.0).unwrap();
        let budget = AtomicBudget::new(&policy);

        assert_eq!(budget.remaining_usd(), 0.0);
        assert!(!budget.has_remaining());
        assert!(budget.charge_usd(0.01).is_err());
        assert!(budget.reserve(0.01).is_err());
    }

    /// The parent must not hand the same budget to two children. Before the
    /// ledger, `reserve` charged the parent and returned a detached child, so
    /// conservation held only for the USD axis and only because `reserve` took
    /// a lock; nothing recorded that a reservation was outstanding.
    #[test]
    fn reservations_cannot_be_double_spent() {
        let parent = AtomicBudget::new(&test_policy(10.0));
        let first = parent.reserve(6.0).unwrap();
        let second = parent.reserve(6.0);
        assert!(
            matches!(second, Err(NucleusError::BudgetExhausted { .. })),
            "a second reservation over the remainder must be refused, got {second:?}"
        );
        // And the refusal changed nothing.
        assert_eq!(parent.live_reservations(), 1);
        assert!((parent.remaining_usd() - 4.0).abs() < 0.001);
        parent.release(first);
    }

    /// Releasing cannot manufacture budget: the ledger refunds the allocation
    /// and nothing more, so a release can only ever undo its own reservation.
    #[test]
    fn release_cannot_grant_budget() {
        let parent = AtomicBudget::new(&test_policy(5.0));
        parent.charge_usd(5.0).unwrap();
        assert_eq!(parent.remaining_usd(), 0.0);

        let r = parent.reserve(1.0);
        assert!(r.is_err(), "nothing left to reserve");
        assert_eq!(parent.remaining_usd(), 0.0);
    }

    /// `pod_mgmt::create_sub_pod` narrows the child's delegation ceiling
    /// against the parent's live spend. Before the ledger, `reserve` charged
    /// immediately, so an in-flight reservation was part of that number; it
    /// still must be, or a concurrent creation would narrow against a ceiling
    /// that ignores budget already promised elsewhere.
    #[test]
    fn a_live_reservation_counts_as_spend_for_ceiling_narrowing() {
        let parent = AtomicBudget::new(&test_policy(10.0));
        let r = parent.reserve(4.0).unwrap();

        assert!((parent.consumed_usd() - 4.0).abs() < 0.001);
        assert!((parent.remaining_usd() - 6.0).abs() < 0.001);
        // The pair always sums to the parent's max.
        assert!((parent.consumed_usd() + parent.remaining_usd() - 10.0).abs() < 0.001);

        // Handing it back returns it to both sides of the identity.
        parent.release(r);
        assert!(parent.consumed_usd().abs() < 0.001);
        assert!((parent.remaining_usd() - 10.0).abs() < 0.001);
    }

    /// The slot capacity bounds reservations that are in flight at once, not
    /// children ever created — commit frees the slot.
    #[test]
    fn committing_frees_the_slot_so_the_cap_bounds_only_in_flight_work() {
        let parent = AtomicBudget::new(&test_policy(1000.0));
        for _ in 0..(BUDGET_SLOTS * 2) {
            let r = parent.reserve(0.5).unwrap();
            parent.commit(r);
        }
        assert_eq!(parent.live_reservations(), 0);
        // Cast-free on purpose: `.clippy-ratchet.toml` counts numeric casts in
        // tests too, and its target is 0.
        let expected = f64::from(u16::try_from(BUDGET_SLOTS).expect("slot count fits in u16"));
        assert!((parent.consumed_usd() - expected).abs() < 0.001);
    }
}
