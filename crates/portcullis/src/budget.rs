//! Budget constraints lattice for cost and token limits.

use rust_decimal::Decimal;
use std::str::FromStr;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Budget constraints lattice.
///
/// Tracks maximum and consumed cost/token budgets for permission scopes.
/// The meet operation takes the minimum of each limit, ensuring delegated
/// permissions never exceed parent budget.
///
/// # Security
///
/// Uses `Decimal` instead of `f64` to prevent:
/// - Precision exploits (infinitesimal charges that accumulate)
/// - Negative charge attacks (`charge(-1000.0)` doesn't grant budget)
/// - NaN/Infinity injection
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BudgetLattice {
    /// Maximum cost for this permission scope (USD)
    pub max_cost_usd: Decimal,
    /// Cost consumed so far (for tracking)
    #[cfg_attr(feature = "serde", serde(default))]
    pub consumed_usd: Decimal,
    /// Maximum input tokens
    pub max_input_tokens: u64,
    /// Maximum output tokens
    pub max_output_tokens: u64,
}

impl Default for BudgetLattice {
    fn default() -> Self {
        Self {
            max_cost_usd: Decimal::from(5),
            consumed_usd: Decimal::ZERO,
            max_input_tokens: 100_000,
            max_output_tokens: 10_000,
        }
    }
}

impl BudgetLattice {
    /// Create a new budget lattice with the given cost limit in USD.
    pub fn with_cost_limit(max_cost_usd: f64) -> Self {
        Self {
            max_cost_usd: Decimal::from_str(&format!("{:.4}", max_cost_usd))
                .unwrap_or(Decimal::from(5)),
            ..Default::default()
        }
    }

    /// Create a new budget lattice with the given cost limit as Decimal.
    pub fn with_cost_limit_decimal(max_cost_usd: Decimal) -> Self {
        Self {
            max_cost_usd,
            ..Default::default()
        }
    }

    /// Create a new budget lattice with token limits.
    pub fn with_token_limits(max_input_tokens: u64, max_output_tokens: u64) -> Self {
        Self {
            max_input_tokens,
            max_output_tokens,
            ..Default::default()
        }
    }

    /// Meet operation: min of each budget limit.
    ///
    /// The result represents the most restrictive combination of both budgets.
    /// - max values: take minimum (most restrictive)
    /// - consumed values: take maximum (worst case tracking)
    pub fn meet(&self, other: &Self) -> Self {
        Self {
            max_cost_usd: self.max_cost_usd.min(other.max_cost_usd),
            consumed_usd: self.consumed_usd.max(other.consumed_usd),
            max_input_tokens: self.max_input_tokens.min(other.max_input_tokens),
            max_output_tokens: self.max_output_tokens.min(other.max_output_tokens),
        }
    }

    /// Join operation: max of each budget limit (least upper bound).
    ///
    /// The result represents the most permissive combination of both budgets.
    pub fn join(&self, other: &Self) -> Self {
        Self {
            max_cost_usd: self.max_cost_usd.max(other.max_cost_usd),
            consumed_usd: self.consumed_usd.min(other.consumed_usd),
            max_input_tokens: self.max_input_tokens.max(other.max_input_tokens),
            max_output_tokens: self.max_output_tokens.max(other.max_output_tokens),
        }
    }

    /// Check if this lattice is less than or equal to another (partial order).
    pub fn leq(&self, other: &Self) -> bool {
        self.max_cost_usd <= other.max_cost_usd
            && self.max_input_tokens <= other.max_input_tokens
            && self.max_output_tokens <= other.max_output_tokens
    }

    /// Check if there is remaining budget.
    pub fn has_remaining(&self) -> bool {
        self.consumed_usd < self.max_cost_usd
    }

    /// Get remaining budget in USD as Decimal.
    pub fn remaining(&self) -> Decimal {
        (self.max_cost_usd - self.consumed_usd).max(Decimal::ZERO)
    }

    /// Get remaining budget in USD as f64 (for compatibility).
    pub fn remaining_usd(&self) -> f64 {
        use rust_decimal::prelude::ToPrimitive;
        self.remaining().to_f64().unwrap_or(0.0)
    }

    /// Record a cost charge against the budget.
    ///
    /// Returns true if the charge was within budget, false if it exceeded.
    ///
    /// # Security
    ///
    /// - Rejects negative charges (prevents budget inflation attacks)
    /// - Rejects zero charges (no-op, potential abuse vector)
    /// - Uses Decimal for precision (no f64 exploits)
    /// - **Atomic**: Only mutates state on successful charge (monoid action property)
    pub fn charge(&mut self, cost_usd: Decimal) -> bool {
        // Security: reject negative or zero charges
        if cost_usd <= Decimal::ZERO {
            return false;
        }

        let new_consumed = self.consumed_usd + cost_usd;
        if new_consumed > self.max_cost_usd {
            return false; // Don't mutate on failure - preserves monoid action property
        }
        self.consumed_usd = new_consumed;
        true
    }

    /// Record a cost charge against the budget using f64 (convenience method).
    ///
    /// # Security
    ///
    /// Converts to Decimal internally to prevent precision exploits.
    pub fn charge_f64(&mut self, cost_usd: f64) -> bool {
        // Reject negative, zero, NaN, or infinite values
        if !cost_usd.is_finite() || cost_usd <= 0.0 {
            return false;
        }

        let decimal = Decimal::from_str(&format!("{:.6}", cost_usd)).unwrap_or(Decimal::ZERO);

        if decimal <= Decimal::ZERO {
            return false;
        }

        self.charge(decimal)
    }

    /// Record token usage against the budget.
    ///
    /// Returns true if usage is within limits.
    pub fn record_tokens(&self, input_tokens: u64, output_tokens: u64) -> bool {
        input_tokens <= self.max_input_tokens && output_tokens <= self.max_output_tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_budget_meet_takes_minimum() {
        let a = BudgetLattice {
            max_cost_usd: Decimal::from(10),
            max_input_tokens: 100_000,
            max_output_tokens: 10_000,
            ..Default::default()
        };
        let b = BudgetLattice {
            max_cost_usd: Decimal::from(5),
            max_input_tokens: 50_000,
            max_output_tokens: 20_000,
            ..Default::default()
        };

        let result = a.meet(&b);

        assert_eq!(result.max_cost_usd, Decimal::from(5));
        assert_eq!(result.max_input_tokens, 50_000);
        assert_eq!(result.max_output_tokens, 10_000);
    }

    #[test]
    fn test_budget_join_takes_maximum() {
        let a = BudgetLattice {
            max_cost_usd: Decimal::from(10),
            max_input_tokens: 100_000,
            max_output_tokens: 10_000,
            ..Default::default()
        };
        let b = BudgetLattice {
            max_cost_usd: Decimal::from(5),
            max_input_tokens: 50_000,
            max_output_tokens: 20_000,
            ..Default::default()
        };

        let result = a.join(&b);

        assert_eq!(result.max_cost_usd, Decimal::from(10));
        assert_eq!(result.max_input_tokens, 100_000);
        assert_eq!(result.max_output_tokens, 20_000);
    }

    #[test]
    fn test_budget_remaining() {
        let mut budget = BudgetLattice::with_cost_limit(10.0);
        assert_eq!(budget.remaining_usd(), 10.0);

        budget.charge(Decimal::from(3));
        assert_eq!(budget.remaining_usd(), 7.0);

        budget.charge(Decimal::from(7));
        assert_eq!(budget.remaining_usd(), 0.0);
    }

    #[test]
    fn test_budget_charge_returns_within_budget() {
        let mut budget = BudgetLattice::with_cost_limit(5.0);
        assert!(budget.charge(Decimal::from(3)));
        assert!(budget.charge(Decimal::from(2)));
        assert!(!budget.charge(Decimal::from_str("0.01").unwrap())); // Exceeds limit
    }

    #[test]
    fn test_budget_leq() {
        let smaller = BudgetLattice::with_cost_limit(5.0);
        let larger = BudgetLattice::with_cost_limit(10.0);

        assert!(smaller.leq(&larger));
        assert!(!larger.leq(&smaller));
    }

    #[test]
    fn test_budget_rejects_negative_charge() {
        let mut budget = BudgetLattice::with_cost_limit(10.0);
        let initial_consumed = budget.consumed_usd;

        // Attempt to charge negative (budget inflation attack)
        let result = budget.charge(Decimal::from(-1000));

        assert!(!result, "Negative charge should be rejected");
        assert_eq!(
            budget.consumed_usd, initial_consumed,
            "Budget should not change"
        );
    }

    #[test]
    fn test_budget_rejects_zero_charge() {
        let mut budget = BudgetLattice::with_cost_limit(10.0);
        let initial_consumed = budget.consumed_usd;

        // Attempt to charge zero
        let result = budget.charge(Decimal::ZERO);

        assert!(!result, "Zero charge should be rejected");
        assert_eq!(
            budget.consumed_usd, initial_consumed,
            "Budget should not change"
        );
    }

    #[test]
    fn test_budget_f64_charge_rejects_nan() {
        let mut budget = BudgetLattice::with_cost_limit(10.0);
        let initial_consumed = budget.consumed_usd;

        // Attempt to charge NaN
        let result = budget.charge_f64(f64::NAN);

        assert!(!result, "NaN charge should be rejected");
        assert_eq!(
            budget.consumed_usd, initial_consumed,
            "Budget should not change"
        );
    }

    #[test]
    fn test_budget_f64_charge_rejects_infinity() {
        let mut budget = BudgetLattice::with_cost_limit(10.0);

        assert!(
            !budget.charge_f64(f64::INFINITY),
            "Infinity should be rejected"
        );
        assert!(
            !budget.charge_f64(f64::NEG_INFINITY),
            "Negative infinity should be rejected"
        );
    }

    #[test]
    fn test_budget_f64_charge_rejects_negative() {
        let mut budget = BudgetLattice::with_cost_limit(10.0);
        let initial_consumed = budget.consumed_usd;

        let result = budget.charge_f64(-5.0);

        assert!(!result, "Negative f64 charge should be rejected");
        assert_eq!(
            budget.consumed_usd, initial_consumed,
            "Budget should not change"
        );
    }

    #[test]
    fn test_budget_charge_is_atomic() {
        // Verifies the monoid action property: charge only mutates on success
        let mut budget = BudgetLattice::with_cost_limit(5.0);

        // Successful charge mutates
        assert!(budget.charge(Decimal::from(3)));
        assert_eq!(budget.consumed_usd, Decimal::from(3));

        // Failed charge (exceeds budget) must NOT mutate
        let before = budget.consumed_usd;
        assert!(!budget.charge(Decimal::from(10))); // Would exceed 5.0 limit
        assert_eq!(
            budget.consumed_usd, before,
            "Failed charge must not mutate consumed_usd (atomicity violation)"
        );

        // Budget should still allow charges up to remaining
        assert!(budget.charge(Decimal::from(2))); // 3 + 2 = 5, at limit
        assert_eq!(budget.consumed_usd, Decimal::from(5));

        // Now at limit, any positive charge should fail without mutation
        let at_limit = budget.consumed_usd;
        assert!(!budget.charge(Decimal::from_str("0.01").unwrap()));
        assert_eq!(
            budget.consumed_usd, at_limit,
            "Charge at limit must not mutate"
        );
    }
}
