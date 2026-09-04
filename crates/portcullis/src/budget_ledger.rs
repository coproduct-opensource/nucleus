//! Budget conservation across spawn (#2426, #2445).
//!
//! # Why a ledger, not a token field
//!
//! A [`LatticeCertificate`](crate::certificate::LatticeCertificate) carries
//! `budget.max_cost_usd` as an attenuating dimension, and
//! [`PermissionLattice::delegate_to`](crate::PermissionLattice::delegate_to)
//! refuses a child that asks for more than the parent has remaining. But
//! `delegate_to` takes `&self`: it *reads* the parent's remaining budget and
//! decrements nothing. A parent that spawns N children each within its
//! remaining budget hands out up to N× that budget. No stateless credential
//! can conserve a counter — the IETF attenuating-agent-token draft says as
//! much and pushes quotas to "deployment-specific shared state". That shared
//! state is this ledger, held by the one enforcement point that actually
//! creates pods.
//!
//! # The invariant
//!
//! For a parent with `max` and `consumed` (`consumed ≤ max`):
//!
//! ```text
//!   Σ live child allocations + consumed ≤ max        (at all times)
//! ```
//!
//! [`LedgerCore::try_allocate`] admits a child only while that holds;
//! [`LedgerCore::release`] retires a child's allocation, folding what the
//! child actually spent into `consumed` (never more than was allocated) and
//! refunding the rest. Proven over the shipped type by
//! `proof_budget_ledger_conserves` / `proof_budget_ledger_release_conserves`
//! in `kani.rs`.
//!
//! # Shape
//!
//! [`LedgerCore`] is the proof subject: fixed-slot, integer micro-USD, no
//! heap. `BTreeMap` is intractable for bounded model checking (the same
//! reason `CapabilityLattice::extensions` is `cfg(not(kani))`), and
//! `rust_decimal::Decimal` arithmetic is far more expensive to unroll than
//! `u64`. [`BudgetLedger`] is the production face: a `Decimal` boundary over
//! the same core, with rounding chosen so that every conversion errs toward
//! *less* budget for the child, never more.

use rust_decimal::prelude::ToPrimitive;
use rust_decimal::Decimal;

use crate::BudgetLattice;

/// Identifier of a child allocation. Callers use `Uuid::as_u128()`.
pub type ChildId = u128;

/// Slot capacity of the production [`BudgetLedger`]. The node's per-parent
/// fan-out cap is enforced *before* allocation (via
/// [`BudgetLedger::live_children`]) and is expected to sit well under this.
pub const LEDGER_SLOTS: usize = 32;

const MICRO_PER_USD: u64 = 1_000_000;

/// Why an allocation or release was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    /// `requested` exceeds what the parent has left after existing
    /// allocations and its own consumption.
    InsufficientBudget {
        /// Micro-USD requested.
        requested_micro: u64,
        /// Micro-USD the parent could still allocate.
        available_micro: u64,
    },
    /// Every slot is taken.
    TooManyChildren {
        /// Slot capacity.
        max: usize,
    },
    /// A live allocation already exists for this child.
    DuplicateChild,
    /// No live allocation exists for this child.
    UnknownChild,
    /// A `Decimal` amount was negative or not representable in micro-USD.
    UnrepresentableAmount,
}

impl core::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InsufficientBudget {
                requested_micro,
                available_micro,
            } => write!(
                f,
                "budget conservation: requested {requested_micro} µUSD, parent can allocate {available_micro} µUSD"
            ),
            Self::TooManyChildren { max } => write!(f, "ledger full ({max} slots)"),
            Self::DuplicateChild => write!(f, "child already has a live allocation"),
            Self::UnknownChild => write!(f, "no live allocation for child"),
            Self::UnrepresentableAmount => write!(f, "amount is negative or not representable"),
        }
    }
}

impl std::error::Error for LedgerError {}

/// The proof subject: a fixed-slot allocation ledger in micro-USD.
///
/// Construct with [`LedgerCore::new`]; the invariant
/// `allocated + consumed ≤ max` is established there (a `consumed > max`
/// parent is clamped to `max`, so it can allocate nothing) and preserved by
/// every method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerCore<const N: usize> {
    parent_max_micro: u64,
    parent_consumed_micro: u64,
    slots: [Option<(ChildId, u64)>; N],
}

impl<const N: usize> LedgerCore<N> {
    /// A ledger for a parent with `parent_max_micro` total and
    /// `parent_consumed_micro` already spent.
    pub const fn new(parent_max_micro: u64, parent_consumed_micro: u64) -> Self {
        let consumed = if parent_consumed_micro > parent_max_micro {
            parent_max_micro
        } else {
            parent_consumed_micro
        };
        Self {
            parent_max_micro,
            parent_consumed_micro: consumed,
            slots: [None; N],
        }
    }

    /// The parent's total budget.
    pub fn parent_max_micro(&self) -> u64 {
        self.parent_max_micro
    }

    /// What the parent itself (plus retired children) has spent.
    pub fn parent_consumed_micro(&self) -> u64 {
        self.parent_consumed_micro
    }

    /// Σ live child allocations.
    pub fn allocated_micro(&self) -> u64 {
        let mut total: u64 = 0;
        let mut i = 0;
        while i < N {
            if let Some((_, amount)) = self.slots[i] {
                total = total.saturating_add(amount);
            }
            i += 1;
        }
        total
    }

    /// What the parent could still hand to a new child.
    pub fn available_micro(&self) -> u64 {
        self.parent_max_micro
            .saturating_sub(self.parent_consumed_micro)
            .saturating_sub(self.allocated_micro())
    }

    /// Number of live child allocations.
    pub fn live_children(&self) -> usize {
        let mut n = 0;
        let mut i = 0;
        while i < N {
            if self.slots[i].is_some() {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// The live allocation for `child`, if any.
    pub fn allocation_of(&self, child: ChildId) -> Option<u64> {
        let mut i = 0;
        while i < N {
            if let Some((id, amount)) = self.slots[i] {
                if id == child {
                    return Some(amount);
                }
            }
            i += 1;
        }
        None
    }

    /// Reserve `amount_micro` for `child`. Succeeds iff the invariant still
    /// holds afterwards; on any error nothing changes.
    pub fn try_allocate(&mut self, child: ChildId, amount_micro: u64) -> Result<(), LedgerError> {
        if self.allocation_of(child).is_some() {
            return Err(LedgerError::DuplicateChild);
        }
        let available = self.available_micro();
        if amount_micro > available {
            return Err(LedgerError::InsufficientBudget {
                requested_micro: amount_micro,
                available_micro: available,
            });
        }
        let mut i = 0;
        while i < N {
            if self.slots[i].is_none() {
                self.slots[i] = Some((child, amount_micro));
                return Ok(());
            }
            i += 1;
        }
        Err(LedgerError::TooManyChildren { max: N })
    }

    /// Retire `child`'s allocation. `consumed_micro` is what the child
    /// actually spent; it is folded into the parent's consumption capped at
    /// the allocation (a child cannot have spent what it was never given).
    /// Returns the refunded remainder.
    pub fn release(&mut self, child: ChildId, consumed_micro: u64) -> Result<u64, LedgerError> {
        let mut i = 0;
        while i < N {
            if let Some((id, amount)) = self.slots[i] {
                if id == child {
                    let spent = if consumed_micro > amount {
                        amount
                    } else {
                        consumed_micro
                    };
                    self.slots[i] = None;
                    self.parent_consumed_micro = self.parent_consumed_micro.saturating_add(spent);
                    return Ok(amount - spent);
                }
            }
            i += 1;
        }
        Err(LedgerError::UnknownChild)
    }

    /// Record the parent's OWN spending (not a child's). Clamped so the
    /// invariant holds: a parent cannot record more than it could have spent
    /// after what it has already handed to children.
    pub fn record_parent_consumed(&mut self, micro: u64) -> u64 {
        let ceiling = self.parent_max_micro.saturating_sub(self.allocated_micro());
        let new_total = self.parent_consumed_micro.saturating_add(micro);
        self.parent_consumed_micro = if new_total > ceiling {
            ceiling
        } else {
            new_total
        };
        self.parent_consumed_micro
    }

    /// The invariant, as a predicate (used by the Kani harnesses and tests).
    pub fn conserves(&self) -> bool {
        self.allocated_micro()
            .saturating_add(self.parent_consumed_micro)
            <= self.parent_max_micro
    }
}

/// Production face of [`LedgerCore`]: `Decimal` USD in, `Decimal` USD out.
///
/// Rounding is deliberately asymmetric so every conversion errs against the
/// child: the parent's `max` rounds DOWN, a child's requested amount rounds
/// UP, and a child's reported consumption rounds UP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetLedger {
    core: LedgerCore<LEDGER_SLOTS>,
}

impl BudgetLedger {
    /// A ledger for a parent whose authority carries `budget`.
    pub fn for_parent(budget: &BudgetLattice) -> Self {
        let max = usd_to_micro_floor(budget.max_cost_usd).unwrap_or(0);
        let consumed = usd_to_micro_ceil(budget.consumed_usd).unwrap_or(u64::MAX);
        Self {
            core: LedgerCore::new(max, consumed),
        }
    }

    /// The underlying proof subject.
    pub fn core(&self) -> &LedgerCore<LEDGER_SLOTS> {
        &self.core
    }

    /// See [`LedgerCore::try_allocate`].
    pub fn try_allocate(&mut self, child: ChildId, amount_usd: Decimal) -> Result<(), LedgerError> {
        let micro = usd_to_micro_ceil(amount_usd).ok_or(LedgerError::UnrepresentableAmount)?;
        self.core.try_allocate(child, micro)
    }

    /// See [`LedgerCore::release`]. Returns the refunded USD.
    pub fn release(
        &mut self,
        child: ChildId,
        consumed_usd: Decimal,
    ) -> Result<Decimal, LedgerError> {
        let micro = usd_to_micro_ceil(consumed_usd).ok_or(LedgerError::UnrepresentableAmount)?;
        self.core.release(child, micro).map(micro_to_usd)
    }

    /// See [`LedgerCore::record_parent_consumed`].
    pub fn record_parent_consumed(&mut self, usd: Decimal) -> Result<Decimal, LedgerError> {
        let micro = usd_to_micro_ceil(usd).ok_or(LedgerError::UnrepresentableAmount)?;
        Ok(micro_to_usd(self.core.record_parent_consumed(micro)))
    }

    /// USD the parent could still hand to a new child.
    pub fn available(&self) -> Decimal {
        micro_to_usd(self.core.available_micro())
    }

    /// Σ live child allocations, in USD.
    pub fn allocated(&self) -> Decimal {
        micro_to_usd(self.core.allocated_micro())
    }

    /// Number of live child allocations.
    pub fn live_children(&self) -> usize {
        self.core.live_children()
    }

    /// The live allocation for `child`, in USD.
    pub fn allocation_of(&self, child: ChildId) -> Option<Decimal> {
        self.core.allocation_of(child).map(micro_to_usd)
    }
}

fn usd_to_micro_floor(usd: Decimal) -> Option<u64> {
    if usd.is_sign_negative() {
        return None;
    }
    (usd * Decimal::from(MICRO_PER_USD)).floor().to_u64()
}

fn usd_to_micro_ceil(usd: Decimal) -> Option<u64> {
    if usd.is_sign_negative() {
        return None;
    }
    (usd * Decimal::from(MICRO_PER_USD)).ceil().to_u64()
}

fn micro_to_usd(micro: u64) -> Decimal {
    Decimal::from(micro) / Decimal::from(MICRO_PER_USD)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn usd(s: &str) -> Decimal {
        Decimal::from_str(s).unwrap()
    }

    /// The defect this module exists to close: a parent with $5 remaining
    /// could previously hand $5 to each of N children. With the ledger the
    /// second such child is refused.
    #[test]
    fn fan_out_cannot_multiply_the_parent_budget() {
        let parent = BudgetLattice::with_cost_limit(5.0);
        let mut ledger = BudgetLedger::for_parent(&parent);

        ledger.try_allocate(1, usd("5")).expect("first child fits");
        let second = ledger.try_allocate(2, usd("5"));
        assert!(
            matches!(second, Err(LedgerError::InsufficientBudget { .. })),
            "second full-budget child must be refused, got {second:?}"
        );
        assert_eq!(ledger.available(), Decimal::ZERO);
        assert!(ledger.core().conserves());

        // Non-vacuity: the lattice-level check alone still admits the
        // second child, because `delegate_to` reads and never decrements.
        let mut request = crate::PermissionLattice::permissive();
        request.budget = BudgetLattice::with_cost_limit(5.0);
        let mut parent_perms = crate::PermissionLattice::permissive();
        parent_perms.budget = parent.clone();
        assert!(parent_perms.delegate_to(&request, "first").is_ok());
        assert!(
            parent_perms.delegate_to(&request, "second").is_ok(),
            "the pre-existing gap: delegate_to alone admits both — otherwise this test \
             no longer demonstrates what the ledger adds"
        );
    }

    #[test]
    fn allocations_split_the_parent_and_release_refunds_the_unspent_part() {
        let mut ledger = BudgetLedger::for_parent(&BudgetLattice::with_cost_limit(10.0));
        ledger.try_allocate(1, usd("4")).unwrap();
        ledger.try_allocate(2, usd("6")).unwrap();
        assert_eq!(ledger.live_children(), 2);
        assert_eq!(ledger.available(), Decimal::ZERO);

        // Child 1 spent $1 of its $4: $3 comes back, $1 is now the parent's consumption.
        let refund = ledger.release(1, usd("1")).unwrap();
        assert_eq!(refund, usd("3"));
        assert_eq!(ledger.available(), usd("3"));
        assert_eq!(ledger.core().parent_consumed_micro(), 1_000_000);
        assert!(ledger.core().conserves());

        // A child cannot report having spent more than it was given.
        let refund = ledger.release(2, usd("100")).unwrap();
        assert_eq!(refund, Decimal::ZERO);
        assert_eq!(ledger.core().parent_consumed_micro(), 7_000_000);
        assert!(ledger.core().conserves());
    }

    #[test]
    fn errors_leave_the_ledger_unchanged() {
        let mut ledger = BudgetLedger::for_parent(&BudgetLattice::with_cost_limit(1.0));
        ledger.try_allocate(7, usd("0.5")).unwrap();
        let before = ledger.clone();

        assert_eq!(
            ledger.try_allocate(7, usd("0.1")),
            Err(LedgerError::DuplicateChild)
        );
        assert!(matches!(
            ledger.try_allocate(8, usd("0.6")),
            Err(LedgerError::InsufficientBudget { .. })
        ));
        assert_eq!(ledger.release(9, usd("0")), Err(LedgerError::UnknownChild));
        assert_eq!(
            ledger.try_allocate(8, usd("-1")),
            Err(LedgerError::UnrepresentableAmount)
        );
        assert_eq!(ledger, before);
    }

    #[test]
    fn a_full_ledger_refuses_rather_than_overwrites() {
        let mut core = LedgerCore::<2>::new(100, 0);
        core.try_allocate(1, 10).unwrap();
        core.try_allocate(2, 10).unwrap();
        assert_eq!(
            core.try_allocate(3, 10),
            Err(LedgerError::TooManyChildren { max: 2 })
        );
        assert_eq!(core.allocated_micro(), 20);
    }

    #[test]
    fn rounding_errs_against_the_child() {
        // Parent max rounds DOWN; child request rounds UP.
        let mut budget = BudgetLattice::with_cost_limit_decimal(usd("1.0000004"));
        budget.consumed_usd = Decimal::ZERO;
        let mut ledger = BudgetLedger::for_parent(&budget);
        assert_eq!(ledger.core().parent_max_micro(), 1_000_000);
        assert!(matches!(
            ledger.try_allocate(1, usd("1.0000001")),
            Err(LedgerError::InsufficientBudget { .. })
        ));
        ledger.try_allocate(1, usd("1")).unwrap();
    }

    #[test]
    fn an_overspent_parent_can_allocate_nothing() {
        let mut budget = BudgetLattice::with_cost_limit(1.0);
        budget.consumed_usd = usd("3");
        let mut ledger = BudgetLedger::for_parent(&budget);
        assert_eq!(ledger.available(), Decimal::ZERO);
        assert!(ledger.core().conserves());
        assert!(ledger.try_allocate(1, usd("0.000001")).is_err());
    }

    #[test]
    fn parent_consumption_is_clamped_by_live_allocations() {
        let mut core = LedgerCore::<4>::new(10, 0);
        core.try_allocate(1, 6).unwrap();
        // Parent tries to record $8 of its own spend with only $4 left to it.
        assert_eq!(core.record_parent_consumed(8), 4);
        assert!(core.conserves());
    }
}
