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
//! # Why the quantity is a parameter
//!
//! The invariant above never mentions money. It needs a quantity that can be
//! added, subtracted and compared, and it needs those operations to *saturate*
//! rather than wrap or trap — which is what makes "a child cannot have spent
//! what it was never given" expressible without a signed type.
//!
//! Money is one such quantity and there are about twenty others in this
//! workspace: token allowances, byte ceilings, rate-limit buckets, cost
//! accumulators. They are not all `u64` — the set spans `u32`, `u128`,
//! `usize`, `Decimal`, `f64`, and one that stores micro-USD as a `String`. So
//! "prove it at `u64` and parametricity covers the rest" **does not hold**;
//! the proof transfers through the [`Unit`] laws, and those laws are also the
//! admission criterion. `f64` has no saturating arithmetic and `NaN` breaks
//! `Ord`, so a float quantity is not admissible and must reach a fixed-point
//! unit first — which is exactly what [`BudgetLedger`] already does for
//! `Decimal`.
//!
//! # Shape
//!
//! [`LedgerCore`] is the proof subject: fixed-slot, integer, no heap.
//! `BTreeMap` is intractable for bounded model checking (the same reason
//! `CapabilityLattice::extensions` is `cfg(not(kani))`), and
//! `rust_decimal::Decimal` arithmetic is far more expensive to unroll than a
//! machine integer. This file has **no `cfg(kani)` sites and must keep none**:
//! `kani-divergence.toml` names it as the standard other modules are measured
//! against — *"making the production representation Kani-tractable
//! (fixed-slot / bitmask, as `LedgerCore` did for the budget ledger), not
//! deleting the proof."*
//!
//! [`BudgetLedger`] is the production face: a `Decimal` boundary over
//! `LedgerCore<MicroUsd, LEDGER_SLOTS>`, with rounding chosen so that every
//! conversion errs toward *less* budget for the child, never more.

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

/// The quantity [`BudgetLedger`] conserves: integer micro-USD.
pub type MicroUsd = u64;

/// A quantity a [`LedgerCore`] can conserve.
///
/// # The laws
///
/// These are what the conservation proof actually rests on, so they are stated
/// here rather than assumed of the implementing type. Writing `⊕` for
/// [`Unit::saturating_add`] and `⊖` for [`Unit::saturating_sub`], for all
/// `a`, `b`, `c`:
///
/// ```text
///   L1  identity        a ⊕ ZERO = a
///   L2  annihilation    a ⊖ a    = ZERO
///   L3  decrease        a ⊖ b    ≤ a
///   L4  monotonicity    a        ≤ a ⊕ b
///   L5  commutativity   a ⊕ b    = b ⊕ a
///   L6  associativity   (a ⊕ b) ⊕ c = a ⊕ (b ⊕ c)
/// ```
///
/// L3 and L4 are the two the invariant leans on directly: L3 is why
/// [`LedgerCore::release`] cannot manufacture budget by refunding more than
/// was allocated, and L4 is why `available` can never exceed `max`. L1, L5 and
/// L6 make `allocated` — a fold over the slots — independent of slot order,
/// which is what lets the proof quantify over allocations rather than over
/// sequences of them.
///
/// # Why this is a trait and not a `u64`
///
/// See the module doc: the ~20 linear quantities in this workspace are not all
/// `u64`, so the parametricity argument that would let one proof cover them
/// all is unsound. It transfers through these laws instead. That also makes
/// the laws an **admission criterion**: a quantity that cannot satisfy them —
/// `f64`, whose `NaN` breaks `Ord` and which has no saturating arithmetic —
/// does not belong in a ledger and must be converted first.
///
/// # Why saturating and not checked
///
/// The ledger's job is to refuse, not to trap. Every arithmetic step here is
/// either already bounded by the invariant or is a clamp the invariant needs
/// (`consumed` capped at the allocation, `available` floored at zero).
/// Saturation makes those clamps total, which is what keeps the whole module
/// free of `unwrap`, of overflow branches, and — the property
/// `kani-divergence.toml` measures other modules against — of any `cfg(kani)`.
pub trait Unit: Copy + Ord + Eq + core::fmt::Debug {
    /// The additive identity, and the floor [`Unit::saturating_sub`] clamps to.
    const ZERO: Self;

    /// `self + rhs`, clamped at the type's maximum instead of wrapping.
    fn saturating_add(self, rhs: Self) -> Self;

    /// `self - rhs`, clamped at [`Unit::ZERO`] instead of wrapping.
    fn saturating_sub(self, rhs: Self) -> Self;
}

/// Implement [`Unit`] for an unsigned integer, whose inherent saturating
/// arithmetic satisfies L1–L6 by construction.
macro_rules! impl_unit_for_unsigned {
    ($($t:ty),+ $(,)?) => {$(
        impl Unit for $t {
            const ZERO: Self = 0;
            fn saturating_add(self, rhs: Self) -> Self {
                <$t>::saturating_add(self, rhs)
            }
            fn saturating_sub(self, rhs: Self) -> Self {
                <$t>::saturating_sub(self, rhs)
            }
        }
    )+};
}

// The unsigned integers the workspace's linear quantities actually use.
// Deliberately not `i64`: a signed quantity can represent a negative balance,
// and L2/L3 would then be claims about a value the ledger has no meaning for.
impl_unit_for_unsigned!(u32, u64, u128, usize);

/// Why an allocation or release was refused.
///
/// Generic in the quantity because [`LedgerError::InsufficientBudget`] reports
/// it. Every variant here is one [`LedgerCore`] can actually produce — the
/// conversion failure that used to sit alongside them belongs to the
/// boundary and now lives on [`BudgetError`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError<U> {
    /// `requested` exceeds what the parent has left after existing
    /// allocations and its own consumption.
    InsufficientBudget {
        /// Units requested.
        requested: U,
        /// Units the parent could still allocate.
        available: U,
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
}

impl<U: core::fmt::Debug> core::fmt::Display for LedgerError<U> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InsufficientBudget {
                requested,
                available,
            } => write!(
                f,
                "budget conservation: requested {requested:?}, parent can allocate {available:?}"
            ),
            Self::TooManyChildren { max } => write!(f, "ledger full ({max} slots)"),
            Self::DuplicateChild => write!(f, "child already has a live allocation"),
            Self::UnknownChild => write!(f, "no live allocation for child"),
        }
    }
}

impl<U: core::fmt::Debug> std::error::Error for LedgerError<U> {}

/// Why a [`BudgetLedger`] operation was refused.
///
/// The `Decimal` boundary has one failure the core does not: an amount that
/// does not convert. Keeping it out of [`LedgerError`] means every variant of
/// that type is one [`LedgerCore`] can actually return, which is the same
/// standard this module's own gates apply elsewhere — a declared case nothing
/// produces is indistinguishable from one that was forgotten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetError {
    /// The ledger refused the operation.
    Ledger(LedgerError<MicroUsd>),
    /// A `Decimal` amount was negative, or too large to express in micro-USD.
    UnrepresentableAmount,
}

impl From<LedgerError<MicroUsd>> for BudgetError {
    fn from(e: LedgerError<MicroUsd>) -> Self {
        Self::Ledger(e)
    }
}

impl core::fmt::Display for BudgetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            // The generic core cannot name a unit, so the refusal it renders
            // is bare numbers. This is the layer that KNOWS the unit, so it
            // puts it back rather than letting the message get worse for the
            // one instantiation that ships.
            Self::Ledger(LedgerError::InsufficientBudget {
                requested,
                available,
            }) => write!(
                f,
                "budget conservation: requested {requested} µUSD, \
                 parent can allocate {available} µUSD"
            ),
            Self::Ledger(e) => e.fmt(f),
            Self::UnrepresentableAmount => {
                write!(f, "amount is negative or not representable")
            }
        }
    }
}

impl std::error::Error for BudgetError {}

/// The proof subject: a fixed-slot allocation ledger over any [`Unit`].
///
/// Construct with [`LedgerCore::new`]; the invariant
/// `allocated + consumed ≤ max` is established there (a `consumed > max`
/// parent is clamped to `max`, so it can allocate nothing) and preserved by
/// every method.
///
/// Not `const fn new`: the clamp compares `parent_consumed > parent_max`, and
/// a generic comparison in a `const fn` needs const trait methods, which are
/// unstable at the workspace MSRV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerCore<U: Unit, const N: usize> {
    parent_max: U,
    parent_consumed: U,
    slots: [Option<(ChildId, U)>; N],
}

impl<U: Unit, const N: usize> LedgerCore<U, N> {
    /// A ledger for a parent with `parent_max` total and `parent_consumed`
    /// already spent.
    pub fn new(parent_max: U, parent_consumed: U) -> Self {
        let consumed = if parent_consumed > parent_max {
            parent_max
        } else {
            parent_consumed
        };
        Self {
            parent_max,
            parent_consumed: consumed,
            slots: [None; N],
        }
    }

    /// The parent's total budget.
    pub fn parent_max_units(&self) -> U {
        self.parent_max
    }

    /// What the parent itself (plus retired children) has spent.
    pub fn parent_consumed_units(&self) -> U {
        self.parent_consumed
    }

    /// Σ live child allocations.
    ///
    /// Order-independent by L1/L5/L6, which is why the proof can quantify over
    /// the set of allocations rather than over sequences of them.
    pub fn allocated_units(&self) -> U {
        let mut total = U::ZERO;
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
    pub fn available_units(&self) -> U {
        self.parent_max
            .saturating_sub(self.parent_consumed)
            .saturating_sub(self.allocated_units())
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
    pub fn allocation_of(&self, child: ChildId) -> Option<U> {
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

    /// Reserve `amount` for `child`. Succeeds iff the invariant still holds
    /// afterwards; on any error nothing changes.
    pub fn try_allocate(&mut self, child: ChildId, amount: U) -> Result<(), LedgerError<U>> {
        if self.allocation_of(child).is_some() {
            return Err(LedgerError::DuplicateChild);
        }
        let available = self.available_units();
        if amount > available {
            return Err(LedgerError::InsufficientBudget {
                requested: amount,
                available,
            });
        }
        let mut i = 0;
        while i < N {
            if self.slots[i].is_none() {
                self.slots[i] = Some((child, amount));
                return Ok(());
            }
            i += 1;
        }
        Err(LedgerError::TooManyChildren { max: N })
    }

    /// Retire `child`'s allocation. `consumed` is what the child actually
    /// spent; it is folded into the parent's consumption capped at the
    /// allocation (a child cannot have spent what it was never given).
    /// Returns the refunded remainder.
    pub fn release(&mut self, child: ChildId, consumed: U) -> Result<U, LedgerError<U>> {
        let mut i = 0;
        while i < N {
            if let Some((id, amount)) = self.slots[i] {
                if id == child {
                    let spent = if consumed > amount { amount } else { consumed };
                    self.slots[i] = None;
                    self.parent_consumed = self.parent_consumed.saturating_add(spent);
                    // Saturating, not `-`: `spent ≤ amount` holds by the clamp
                    // above, but `Sub` is not in the `Unit` laws, and a total
                    // operation here is what keeps the module free of overflow
                    // branches — and so of `cfg(kani)`.
                    return Ok(amount.saturating_sub(spent));
                }
            }
            i += 1;
        }
        Err(LedgerError::UnknownChild)
    }

    /// Record the parent's OWN spending (not a child's). Clamped so the
    /// invariant holds: a parent cannot record more than it could have spent
    /// after what it has already handed to children.
    pub fn record_parent_consumed(&mut self, amount: U) -> U {
        let ceiling = self.parent_max.saturating_sub(self.allocated_units());
        let new_total = self.parent_consumed.saturating_add(amount);
        self.parent_consumed = if new_total > ceiling {
            ceiling
        } else {
            new_total
        };
        self.parent_consumed
    }

    /// The invariant, as a predicate (used by the Kani harnesses and tests).
    pub fn conserves(&self) -> bool {
        self.allocated_units().saturating_add(self.parent_consumed) <= self.parent_max
    }
}

/// Production face of [`LedgerCore`]: `Decimal` USD in, `Decimal` USD out.
///
/// Rounding is deliberately asymmetric so every conversion errs against the
/// child: the parent's `max` rounds DOWN, a child's requested amount rounds
/// UP, and a child's reported consumption rounds UP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetLedger {
    core: LedgerCore<MicroUsd, LEDGER_SLOTS>,
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
    pub fn core(&self) -> &LedgerCore<MicroUsd, LEDGER_SLOTS> {
        &self.core
    }

    /// See [`LedgerCore::try_allocate`].
    pub fn try_allocate(&mut self, child: ChildId, amount_usd: Decimal) -> Result<(), BudgetError> {
        let micro = usd_to_micro_ceil(amount_usd).ok_or(BudgetError::UnrepresentableAmount)?;
        Ok(self.core.try_allocate(child, micro)?)
    }

    /// See [`LedgerCore::release`]. Returns the refunded USD.
    pub fn release(
        &mut self,
        child: ChildId,
        consumed_usd: Decimal,
    ) -> Result<Decimal, BudgetError> {
        let micro = usd_to_micro_ceil(consumed_usd).ok_or(BudgetError::UnrepresentableAmount)?;
        Ok(micro_to_usd(self.core.release(child, micro)?))
    }

    /// See [`LedgerCore::record_parent_consumed`].
    pub fn record_parent_consumed(&mut self, usd: Decimal) -> Result<Decimal, BudgetError> {
        let micro = usd_to_micro_ceil(usd).ok_or(BudgetError::UnrepresentableAmount)?;
        Ok(micro_to_usd(self.core.record_parent_consumed(micro)))
    }

    /// USD the parent could still hand to a new child.
    pub fn available(&self) -> Decimal {
        micro_to_usd(self.core.available_units())
    }

    /// Σ live child allocations, in USD.
    pub fn allocated(&self) -> Decimal {
        micro_to_usd(self.core.allocated_units())
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

fn usd_to_micro_floor(usd: Decimal) -> Option<MicroUsd> {
    if usd.is_sign_negative() {
        return None;
    }
    (usd * Decimal::from(MICRO_PER_USD)).floor().to_u64()
}

fn usd_to_micro_ceil(usd: Decimal) -> Option<MicroUsd> {
    if usd.is_sign_negative() {
        return None;
    }
    (usd * Decimal::from(MICRO_PER_USD)).ceil().to_u64()
}

fn micro_to_usd(micro: MicroUsd) -> Decimal {
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
            matches!(
                second,
                Err(BudgetError::Ledger(LedgerError::InsufficientBudget { .. }))
            ),
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
        assert_eq!(ledger.core().parent_consumed_units(), 1_000_000);
        assert!(ledger.core().conserves());

        // A child cannot report having spent more than it was given.
        let refund = ledger.release(2, usd("100")).unwrap();
        assert_eq!(refund, Decimal::ZERO);
        assert_eq!(ledger.core().parent_consumed_units(), 7_000_000);
        assert!(ledger.core().conserves());
    }

    #[test]
    fn errors_leave_the_ledger_unchanged() {
        let mut ledger = BudgetLedger::for_parent(&BudgetLattice::with_cost_limit(1.0));
        ledger.try_allocate(7, usd("0.5")).unwrap();
        let before = ledger.clone();

        assert_eq!(
            ledger.try_allocate(7, usd("0.1")),
            Err(BudgetError::Ledger(LedgerError::DuplicateChild))
        );
        assert!(matches!(
            ledger.try_allocate(8, usd("0.6")),
            Err(BudgetError::Ledger(LedgerError::InsufficientBudget { .. }))
        ));
        assert_eq!(
            ledger.release(9, usd("0")),
            Err(BudgetError::Ledger(LedgerError::UnknownChild))
        );
        assert_eq!(
            ledger.try_allocate(8, usd("-1")),
            Err(BudgetError::UnrepresentableAmount)
        );
        assert_eq!(ledger, before);
    }

    #[test]
    fn a_full_ledger_refuses_rather_than_overwrites() {
        let mut core = LedgerCore::<u64, 2>::new(100, 0);
        core.try_allocate(1, 10).unwrap();
        core.try_allocate(2, 10).unwrap();
        assert_eq!(
            core.try_allocate(3, 10),
            Err(LedgerError::TooManyChildren { max: 2 })
        );
        assert_eq!(core.allocated_units(), 20);
    }

    #[test]
    fn rounding_errs_against_the_child() {
        // Parent max rounds DOWN; child request rounds UP.
        let mut budget = BudgetLattice::with_cost_limit_decimal(usd("1.0000004"));
        budget.consumed_usd = Decimal::ZERO;
        let mut ledger = BudgetLedger::for_parent(&budget);
        assert_eq!(ledger.core().parent_max_units(), 1_000_000);
        assert!(matches!(
            ledger.try_allocate(1, usd("1.0000001")),
            Err(BudgetError::Ledger(LedgerError::InsufficientBudget { .. }))
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
        let mut core = LedgerCore::<u64, 4>::new(10, 0);
        core.try_allocate(1, 6).unwrap();
        // Parent tries to record $8 of its own spend with only $4 left to it.
        assert_eq!(core.record_parent_consumed(8), 4);
        assert!(core.conserves());
    }

    // ── The `Unit` laws ───────────────────────────────────────────────────
    //
    // ADR 0006 withdrew the claim that proving conservation at `u64` covers
    // every candidate quantity "by parametricity": the ~20 linear quantities
    // in this workspace are `u64`, `usize`, `u32`, `u128`, `Decimal`, `f64`
    // and one `String`, and `usize` is not `u64` on every target. The proof
    // transfers through the laws below instead, so the laws have to be
    // discharged rather than assumed.

    /// Check L1–L6 over `corpus`, which must include the type's saturation
    /// boundary. That boundary is the whole point: L4 (`a ≤ a ⊕ b`) and L6
    /// (associativity) are trivially true for unbounded arithmetic and are
    /// exactly where a *wrapping* or *checked* implementation would fail, so a
    /// corpus of small values would prove nothing about the property the
    /// ledger actually relies on.
    fn check_unit_laws<U: Unit>(corpus: &[U]) {
        for &a in corpus {
            assert_eq!(a.saturating_add(U::ZERO), a, "L1 identity: {a:?}");
            assert_eq!(a.saturating_sub(a), U::ZERO, "L2 annihilation: {a:?}");
            for &b in corpus {
                assert!(a.saturating_sub(b) <= a, "L3 decrease: {a:?} {b:?}");
                assert!(a <= a.saturating_add(b), "L4 monotonicity: {a:?} {b:?}");
                assert_eq!(
                    a.saturating_add(b),
                    b.saturating_add(a),
                    "L5 commutativity: {a:?} {b:?}"
                );
                for &c in corpus {
                    assert_eq!(
                        a.saturating_add(b).saturating_add(c),
                        a.saturating_add(b.saturating_add(c)),
                        "L6 associativity: {a:?} {b:?} {c:?}"
                    );
                }
            }
        }
    }

    /// The production refusal keeps its unit. `LedgerError` is generic now and
    /// renders bare numbers; `BudgetError` is the layer that knows these are
    /// micro-USD, and `pod_authority::ledger_denial` puts this string in front
    /// of a person.
    #[test]
    fn the_production_refusal_still_names_its_unit() {
        let mut ledger = BudgetLedger::for_parent(&BudgetLattice::with_cost_limit(1.0));
        let Err(e) = ledger.try_allocate(1, usd("2")) else {
            panic!("a $2 child must not fit in a $1 parent");
        };
        assert_eq!(
            e.to_string(),
            "budget conservation: requested 2000000 µUSD, parent can allocate 1000000 µUSD"
        );
    }

    #[test]
    fn every_unit_impl_satisfies_the_laws_including_at_saturation() {
        check_unit_laws(&[0u32, 1, 2, u32::MAX / 2, u32::MAX - 1, u32::MAX]);
        check_unit_laws(&[0u64, 1, 2, u64::MAX / 2, u64::MAX - 1, u64::MAX]);
        check_unit_laws(&[0u128, 1, 2, u128::MAX / 2, u128::MAX - 1, u128::MAX]);
        check_unit_laws(&[0usize, 1, 2, usize::MAX / 2, usize::MAX - 1, usize::MAX]);
    }

    /// The claim the laws are supposed to buy: conservation is a property of
    /// the laws, not of `u64`. Same scenario as
    /// `fan_out_cannot_multiply_the_parent_budget`, at a narrower unit — a
    /// token allowance rather than money.
    #[test]
    fn conservation_holds_at_a_unit_that_is_not_u64() {
        let mut core = LedgerCore::<u32, 4>::new(5, 0);
        core.try_allocate(1, 5).expect("first child fits");
        assert_eq!(
            core.try_allocate(2, 5),
            Err(LedgerError::InsufficientBudget {
                requested: 5,
                available: 0
            }),
            "a second full-budget child must be refused at u32 exactly as at u64"
        );
        assert!(core.conserves());

        let refund = core.release(1, 1).unwrap();
        assert_eq!(refund, 4);
        assert_eq!(core.parent_consumed_units(), 1);
        assert!(core.conserves());
    }

    /// Saturation must not manufacture budget. At `u32::MAX` the adds in
    /// `allocated_units` clamp instead of wrapping; a wrapping implementation
    /// would let `allocated + consumed` fold back under `max` and report
    /// `conserves()` on a ledger that had over-allocated.
    #[test]
    fn saturation_cannot_be_used_to_manufacture_budget() {
        let mut core = LedgerCore::<u32, 4>::new(u32::MAX, 0);
        core.try_allocate(1, u32::MAX).unwrap();
        assert_eq!(core.available_units(), 0);
        assert_eq!(
            core.try_allocate(2, 1),
            Err(LedgerError::InsufficientBudget {
                requested: 1,
                available: 0
            })
        );
        assert!(core.conserves());
    }

    /// A parent constructed already over its ceiling can allocate nothing,
    /// at any unit. This is the clamp `new` establishes, and it is the one
    /// place the constructor needs `Ord` — the reason `new` cannot be `const`
    /// at the workspace MSRV.
    #[test]
    fn an_overspent_parent_is_clamped_at_construction_for_any_unit() {
        let core = LedgerCore::<u128, 2>::new(10, 99);
        assert_eq!(core.parent_consumed_units(), 10);
        assert_eq!(core.available_units(), 0);
        assert!(core.conserves());
    }
}
