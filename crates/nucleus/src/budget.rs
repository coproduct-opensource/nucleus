//! Atomic budget enforcement.
//!
//! Unlike `lattice_guard::BudgetLattice` which uses `&mut self` for charging,
//! `AtomicBudget` uses atomic operations to prevent concurrent agents from
//! racing to exhaust budgets.
//!
//! ## Thread Safety
//!
//! Multiple threads can call `charge()` concurrently. The atomic compare-and-swap
//! ensures that:
//! - No charge succeeds if it would exceed the budget
//! - The total charged never exceeds `max_usd`
//! - Failed charges do not modify the consumed amount

use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{NucleusError, Result};
use lattice_guard::BudgetLattice;

/// Thread-safe budget enforcement with atomic operations.
///
/// This wraps a `BudgetLattice` policy and provides atomic charging operations
/// that cannot be bypassed through concurrent access.
pub struct AtomicBudget {
    /// Maximum allowed in micro-dollars (USD * 1_000_000)
    max_micro_usd: u64,
    /// Consumed amount in micro-dollars (atomic)
    consumed_micro_usd: AtomicU64,
    /// Maximum input tokens
    max_input_tokens: u64,
    /// Consumed input tokens (atomic)
    consumed_input_tokens: AtomicU64,
    /// Maximum output tokens
    max_output_tokens: u64,
    /// Consumed output tokens (atomic)
    consumed_output_tokens: AtomicU64,
    /// Lock for reservation operations (more complex than simple charges)
    reservation_lock: Mutex<()>,
}

impl AtomicBudget {
    /// Create a new atomic budget from a policy.
    ///
    /// The policy's `max_cost_usd` and token limits are used as the enforcement bounds.
    /// The initial consumed amount is taken from the policy (usually 0).
    pub fn new(policy: &BudgetLattice) -> Self {
        // Convert Decimal to micro-dollars for atomic operations
        let max_micro = policy.max_cost_usd.to_string().parse::<f64>().unwrap_or(0.0);
        let consumed_micro = policy.consumed_usd.to_string().parse::<f64>().unwrap_or(0.0);

        Self {
            max_micro_usd: (max_micro * 1_000_000.0) as u64,
            consumed_micro_usd: AtomicU64::new((consumed_micro * 1_000_000.0) as u64),
            max_input_tokens: policy.max_input_tokens,
            consumed_input_tokens: AtomicU64::new(0),
            max_output_tokens: policy.max_output_tokens,
            consumed_output_tokens: AtomicU64::new(0),
            reservation_lock: Mutex::new(()),
        }
    }

    /// Atomically charge an amount in USD.
    ///
    /// Returns `Ok(())` if the charge succeeded, or an error if:
    /// - The charge would exceed the budget
    /// - The amount is negative, zero, NaN, or infinite
    ///
    /// This operation is atomic: concurrent calls will not race.
    pub fn charge_usd(&self, amount: f64) -> Result<()> {
        // Validate amount
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

        let amount_micro = (amount * 1_000_000.0) as u64;
        self.charge_micro_usd(amount_micro)
    }

    /// Atomically charge an amount in micro-dollars (USD * 1_000_000).
    ///
    /// This is the core atomic operation. Uses compare-and-swap to ensure
    /// thread safety.
    fn charge_micro_usd(&self, amount_micro: u64) -> Result<()> {
        loop {
            let current = self.consumed_micro_usd.load(Ordering::Acquire);
            let new_total = current.saturating_add(amount_micro);

            if new_total > self.max_micro_usd {
                return Err(NucleusError::BudgetExhausted {
                    requested: amount_micro as f64 / 1_000_000.0,
                    remaining: (self.max_micro_usd - current) as f64 / 1_000_000.0,
                });
            }

            // Compare-and-swap: only succeed if no one else changed it
            match self.consumed_micro_usd.compare_exchange_weak(
                current,
                new_total,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(_) => continue, // Someone else charged, retry
            }
        }
    }

    /// Atomically charge input tokens.
    pub fn charge_input_tokens(&self, tokens: u64) -> Result<()> {
        loop {
            let current = self.consumed_input_tokens.load(Ordering::Acquire);
            let new_total = current.saturating_add(tokens);

            if new_total > self.max_input_tokens {
                return Err(NucleusError::BudgetExhausted {
                    requested: tokens as f64,
                    remaining: (self.max_input_tokens - current) as f64,
                });
            }

            match self.consumed_input_tokens.compare_exchange_weak(
                current,
                new_total,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(_) => continue,
            }
        }
    }

    /// Atomically charge output tokens.
    pub fn charge_output_tokens(&self, tokens: u64) -> Result<()> {
        loop {
            let current = self.consumed_output_tokens.load(Ordering::Acquire);
            let new_total = current.saturating_add(tokens);

            if new_total > self.max_output_tokens {
                return Err(NucleusError::BudgetExhausted {
                    requested: tokens as f64,
                    remaining: (self.max_output_tokens - current) as f64,
                });
            }

            match self.consumed_output_tokens.compare_exchange_weak(
                current,
                new_total,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(_) => continue,
            }
        }
    }

    /// Get remaining USD budget.
    pub fn remaining_usd(&self) -> f64 {
        let consumed = self.consumed_micro_usd.load(Ordering::Acquire);
        (self.max_micro_usd - consumed) as f64 / 1_000_000.0
    }

    /// Get consumed USD amount.
    pub fn consumed_usd(&self) -> f64 {
        let consumed = self.consumed_micro_usd.load(Ordering::Acquire);
        consumed as f64 / 1_000_000.0
    }

    /// Check if budget has remaining funds (without charging).
    pub fn has_remaining(&self) -> bool {
        self.consumed_micro_usd.load(Ordering::Acquire) < self.max_micro_usd
    }

    /// Reserve a portion of the budget for a sub-operation.
    ///
    /// Returns a new `AtomicBudget` with the reserved amount as its max.
    /// The reservation is deducted from this budget atomically.
    ///
    /// This is used for delegation: the parent reserves budget for a child agent.
    pub fn reserve(&self, amount_usd: f64) -> Result<AtomicBudget> {
        // Use lock for reservation to prevent complex races
        let _guard = self.reservation_lock.lock();

        // First charge from parent
        self.charge_usd(amount_usd)?;

        // Create child budget with reserved amount
        Ok(AtomicBudget {
            max_micro_usd: (amount_usd * 1_000_000.0) as u64,
            consumed_micro_usd: AtomicU64::new(0),
            max_input_tokens: self.max_input_tokens / 2, // Give half of remaining
            consumed_input_tokens: AtomicU64::new(0),
            max_output_tokens: self.max_output_tokens / 2,
            consumed_output_tokens: AtomicU64::new(0),
            reservation_lock: Mutex::new(()),
        })
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

        let child = parent.reserve(3.0).unwrap();
        assert!((parent.remaining_usd() - 7.0).abs() < 0.001);
        assert!((child.remaining_usd() - 3.0).abs() < 0.001);

        // Child can charge from its reservation
        assert!(child.charge_usd(2.0).is_ok());
        assert!(child.charge_usd(2.0).is_err()); // Exceeds child's 3.0
    }
}
