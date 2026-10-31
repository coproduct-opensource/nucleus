//! One conserved balance for a pod's own effects and delegated allocations.
//!
//! # Reserve, then settle (2026-10-31)
//!
//! A metered call's price is known only after it. So before the call the pod
//! reserves the call's ceiling, the most it can cost ([`commit_holding`]): the
//! tariff is debited and the rest is held, and the call is refused before any
//! upstream traffic if the two do not fit. After the call, [`settle`] releases
//! the hold and debits the call's charge, which is at most the hold. The
//! conserved quantity is `consumed + held + Σ children ≤ max`, and the
//! checkpoint carries `consumed + held`, so a node that dies mid-call charges
//! that call its ceiling.
//!
//! Until this change a call was refused only once the balance was already
//! zero. With a zero tariff, a pod with one micro-USD left could run a call
//! costing its whole ceiling, and the ledger, which clamps at its maximum,
//! recorded less than was spent.
//!
//! [`commit_holding`]: SharedBudget::commit_holding
//! [`settle`]: SharedBudget::settle
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use portcullis::BudgetLedger;
use rust_decimal::Decimal;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct SharedBudget {
    state: Arc<Mutex<State>>,
    checkpoint: Option<(Uuid, PathBuf)>,
}

struct State {
    ledger: BudgetLedger,
    faulted: bool,
    /// Micro-USD held for calls in flight: each one's ceiling above its tariff,
    /// from its commit until its outcome settles. Neither consumed nor
    /// available to another call or to a child.
    held: u64,
    /// Micro-USD that calls cost beyond what they reserved. A ceiling bounds a
    /// call's price, so this should stay zero. If it does not, it is kept
    /// here, persisted and logged as an alarm, never absorbed by a clamp.
    overrun: u64,
}

impl State {
    fn fresh(ledger: BudgetLedger) -> Self {
        Self {
            ledger,
            faulted: false,
            held: 0,
            overrun: 0,
        }
    }

    /// What a new call or a new child could still take.
    fn spendable(&self) -> Decimal {
        (self.ledger.available() - micro(self.held)).max(Decimal::ZERO)
    }
}

fn micro(units: u64) -> Decimal {
    Decimal::from_i128_with_scale(i128::from(units), 6)
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u8,
    pod: Uuid,
    /// Consumed plus held: an in-flight call is charged its ceiling on restore.
    consumed_micro: u64,
    /// See `State::overrun`. Written only when nonzero, so the checkpoint of a
    /// pod that never overran still reads under an older runtime.
    #[serde(default, skip_serializing_if = "is_zero")]
    overrun_micro: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl SharedBudget {
    pub(super) fn new(ledger: BudgetLedger, pod: Uuid, dir: &std::path::Path) -> Self {
        Self::with_state(State::fresh(ledger), pod, dir)
    }

    fn with_state(state: State, pod: Uuid, dir: &std::path::Path) -> Self {
        Self {
            state: Arc::new(Mutex::new(state)),
            checkpoint: Some((pod, dir.join("budget-consumption.json"))),
        }
    }

    #[cfg(test)]
    pub(crate) fn memory(ledger: BudgetLedger) -> Self {
        Self {
            state: Arc::new(Mutex::new(State::fresh(ledger))),
            checkpoint: None,
        }
    }

    pub(super) fn restore(
        mut ledger: BudgetLedger,
        pod: Uuid,
        dir: &std::path::Path,
    ) -> Result<Self, &'static str> {
        let mut overrun = 0;
        match std::fs::read(dir.join("budget-consumption.json")) {
            Ok(bytes) => {
                let record: Checkpoint =
                    serde_json::from_slice(&bytes).map_err(|_| "budget checkpoint malformed")?;
                if record.version != 1
                    || record.pod != pod
                    || record.consumed_micro > ledger.core().parent_max_units()
                {
                    return Err("budget checkpoint invalid");
                }
                let additional = record
                    .consumed_micro
                    .saturating_sub(ledger.core().parent_consumed_units());
                ledger
                    .record_parent_consumed(micro(additional))
                    .map_err(|_| "budget checkpoint unrepresentable")?;
                overrun = record.overrun_micro;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Older runtime history has no conserved consumption checkpoint.
                // Absence is safe only when no host authorization journal exists.
                match std::fs::symlink_metadata(dir.join(nucleus_spec::host_effect::LOG_FILE)) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Ok(_) | Err(_) => return Err("runtime history lacks a budget checkpoint"),
                }
            }
            Err(_) => return Err("budget checkpoint unreadable"),
        }
        let mut state = State::fresh(ledger);
        state.overrun = overrun;
        Ok(Self::with_state(state, pod, dir))
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, String> {
        let state = self.state.lock().map_err(|_| "host budget poisoned")?;
        if state.faulted {
            return Err("host budget storage unavailable".into());
        }
        Ok(state)
    }

    pub(crate) fn snapshot(&self) -> Result<BudgetLedger, String> {
        Ok(self.lock()?.ledger.clone())
    }

    /// What a new call or child could take: the ledger's balance less what
    /// calls in flight hold.
    pub(crate) fn available(&self) -> Result<Decimal, String> {
        Ok(self.lock()?.spendable())
    }

    /// Micro-USD held for calls in flight.
    #[cfg(test)]
    pub(crate) fn held_micro(&self) -> Result<u64, String> {
        Ok(self.lock()?.held)
    }

    /// Micro-USD that calls cost beyond their reservations (an alarm if nonzero).
    #[cfg(test)]
    pub(crate) fn overrun_micro(&self) -> Result<u64, String> {
        Ok(self.lock()?.overrun)
    }

    pub(super) fn live_children(&self) -> Result<usize, String> {
        Ok(self.lock()?.ledger.live_children())
    }

    pub(super) fn try_allocate(&self, child: u128, amount: Decimal) -> Result<(), String> {
        let mut state = self.lock()?;
        // A child cannot take what an in-flight call holds.
        if amount > state.spendable() {
            return Err(format!(
                "insufficient budget: requested {amount}, available {}",
                state.spendable()
            ));
        }
        state
            .ledger
            .try_allocate(child, amount)
            .map_err(|e| e.to_string())
    }

    pub(super) fn release(&self, child: u128, consumed: Decimal) -> Result<Decimal, String> {
        self.lock()?
            .ledger
            .release(child, consumed)
            .map_err(|e| e.to_string())
    }

    /// Debit `amount` with no hold. See [`Self::commit_holding`].
    #[cfg(test)]
    pub(crate) fn commit<T>(
        &self,
        amount: Decimal,
        evidence: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        self.commit_holding(amount, 0, evidence)
    }

    /// Serialize affordability, durable evidence, debit, hold and checkpoint
    /// against child admission. `amount` (the tariff) is debited and `hold`
    /// micro-USD (the rest of the call's ceiling) is reserved, and both must
    /// fit, so a call that could cost more than the pod has left never starts.
    /// The caller must later [`Self::settle`] the same `hold`. No executable
    /// permit escapes until both writes succeed. A failed checkpoint latches
    /// refusal; it cannot create spendable credit.
    pub(crate) fn commit_holding<T>(
        &self,
        amount: Decimal,
        hold: u64,
        evidence: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        let mut state = self.lock()?;
        let spendable = state.spendable();
        if amount < Decimal::ZERO || amount + micro(hold) > spendable || spendable <= Decimal::ZERO
        {
            return Err(if hold > 0 {
                "host budget cannot reserve this call's ceiling".into()
            } else {
                "host budget exhausted for operator call charge".into()
            });
        }
        let record = evidence()?;
        state
            .ledger
            .record_parent_consumed(amount)
            .map_err(|e| e.to_string())?;
        state.held = state.held.saturating_add(hold);
        self.persist(&mut state)?;
        Ok(record)
    }

    /// Settle a call that reserved `hold` micro-USD: release the hold and debit
    /// `debit`, what the call cost above its tariff. A debit within the hold
    /// always fits, since the hold was reserved from the balance; the unused
    /// part is refunded. This cannot refuse for affordability: the spend
    /// already occurred.
    ///
    /// A debit beyond the hold means a ceiling did not bound a price, which
    /// should be impossible. The excess is debited as far as the ledger holds
    /// it (which exhausts the pod), and all of it is kept in `overrun`,
    /// persisted and logged as an alarm, so the ledger's clamp never hides it.
    pub(crate) fn settle(&self, hold: u64, debit: u64) -> Result<(), String> {
        let mut state = self.lock()?;
        if hold > state.held {
            state.faulted = true;
            return Err("host budget settled a hold it never reserved".into());
        }
        state.held -= hold;
        let before = state.ledger.core().parent_consumed_units();
        state
            .ledger
            .record_parent_consumed(micro(debit))
            .map_err(|e| e.to_string())?;
        let recorded = state.ledger.core().parent_consumed_units() - before;
        if debit > hold || recorded < debit {
            let beyond_hold = debit.saturating_sub(hold);
            let unrecorded = debit - recorded;
            let excess = beyond_hold.max(unrecorded);
            state.overrun = state.overrun.saturating_add(excess);
            tracing::error!(
                alarm = "metered_call_overran_its_reservation",
                hold_micro_usd = hold,
                charged_micro_usd = debit,
                beyond_hold_micro_usd = beyond_hold,
                not_in_ledger_micro_usd = unrecorded,
                overrun_total_micro_usd = state.overrun,
                "ALARM: a metered call cost more than the ceiling it reserved"
            );
        }
        self.persist(&mut state)
    }

    pub(super) fn checkpoint(&self) -> Result<(), String> {
        let mut state = self.lock()?;
        self.persist(&mut state)
    }

    fn persist(&self, state: &mut State) -> Result<(), String> {
        if let Some((pod, path)) = &self.checkpoint {
            let checkpoint = Checkpoint {
                version: 1,
                pod: *pod,
                // Capped: only an overrun can push consumed plus held past the
                // maximum, and the overrun is recorded beside it.
                consumed_micro: state
                    .ledger
                    .core()
                    .parent_consumed_units()
                    .saturating_add(state.held)
                    .min(state.ledger.core().parent_max_units()),
                overrun_micro: state.overrun,
            };
            let written = serde_json::to_vec(&checkpoint)
                .map_err(std::io::Error::other)
                .and_then(|bytes| super::write_whole_sync(path, &bytes));
            if let Err(e) = written {
                state.faulted = true;
                return Err(format!("host budget checkpoint failed: {e}"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
