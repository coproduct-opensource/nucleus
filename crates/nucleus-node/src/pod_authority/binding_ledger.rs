//! A binding's ledger, held to the registry in force: its ceiling re-applied at
//! each admission (`receil`, see `registry.rs`) and its allocations charged to
//! the UTC day (`charge_day`, see `daily.rs`). Both run under the authority's
//! lock, on the ledger the admission is about to charge.

use portcullis::BudgetLedger;
use uuid::Uuid;

use super::{ChainLedger, charged, daily, ledger_denial, micro_usd};
use crate::ApiError;

impl ChainLedger {
    pub(super) fn new(ledger: BudgetLedger) -> Self {
        Self {
            ledger,
            retired: Vec::new(),
            days: daily::Days::none_charged(),
        }
    }
}

/// Set a binding's ledger ceiling to `max(ceiling, consumed + allocated)`: the
/// registry decides the ceiling, and nothing already consumed or allocated is
/// rewritten. See `registry.rs`. `live` are the pods whose parent is this
/// ledger; every live allocation must be one of them, or nothing changes and
/// the admission is refused.
///
/// `BudgetLedger` has no way to change its ceiling (its core is the Kani proof
/// subject, and stays so), so the ledger is rebuilt: the new ceiling, the same
/// consumption, the same allocations, each checked equal before the swap.
pub(super) fn receil(
    chain: &mut ChainLedger,
    ceiling_micro: u64,
    live: &[u128],
) -> Result<(), ApiError> {
    let old = chain.ledger.core();
    let (consumed, allocated) = (old.parent_consumed_units(), old.allocated_units());
    let target = ceiling_micro.max(consumed.saturating_add(allocated));
    if target == old.parent_max_units() {
        return Ok(());
    }
    let mut fresh = charged(
        BudgetLedger::for_parent(&portcullis::BudgetLattice::with_cost_limit_decimal(
            micro_usd(target),
        )),
        consumed,
    );
    for child in live {
        if let Some(amount) = chain.ledger.allocation_of(*child) {
            fresh.try_allocate(*child, amount).map_err(ledger_denial)?;
        }
    }
    let new = fresh.core();
    if new.parent_consumed_units() != consumed
        || new.allocated_units() != allocated
        || new.live_children() != old.live_children()
    {
        tracing::error!(
            consumed,
            allocated,
            "a binding's ledger could not be carried to its registry ceiling exactly; refused"
        );
        return Err(ledger_denial(
            "the binding's ledger could not be carried to its current ceiling",
        ));
    }
    chain.ledger = fresh;
    Ok(())
}

/// Charge `child_id`'s allocation, just reserved in `chain`'s ledger, to `today`
/// for `binding`'s per-day allowance, or hand the reservation back and refuse if
/// it does not fit what is left of today's. Charged whether or not the binding
/// sets an allowance, so one set later counts the day's earlier admissions.
pub(super) fn charge_day(
    chain: &mut ChainLedger,
    binding: &crate::federation_ingress::CallerBinding,
    child_id: Uuid,
    today: chrono::NaiveDate,
) -> Result<(), ApiError> {
    // Read back from the ledger so the day is charged exactly what it reserved,
    // with the ledger's rounding. No allocation to read is "could not look",
    // never "charged nothing" (ADR 0007 A-1): refused, the reservation handed back.
    let Some(micro) = chain.ledger.core().allocation_of(child_id.as_u128()) else {
        let _ = chain
            .ledger
            .release(child_id.as_u128(), rust_decimal::Decimal::ZERO);
        return Err(ledger_denial(
            "the reservation to charge to today's allowance is not in the ledger",
        ));
    };
    let spent = chain.days.charged(today);
    if let Some(limit) = binding.daily_max_micro()
        && spent.saturating_add(micro) > limit
    {
        let _ = chain
            .ledger
            .release(child_id.as_u128(), rust_decimal::Decimal::ZERO);
        return Err(ApiError::Authority(format!(
            "daily allowance: requested {} USD, {} USD of {} USD left for {today} (UTC)",
            micro_usd(micro),
            micro_usd(limit.saturating_sub(spent)),
            micro_usd(limit),
        )));
    }
    chain.days.charge(child_id, today, micro);
    Ok(())
}
