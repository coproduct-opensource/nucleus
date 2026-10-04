//! One conserved balance for a pod's own effects and delegated allocations.
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
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u8,
    pod: Uuid,
    consumed_micro: u64,
}

impl SharedBudget {
    pub(super) fn new(ledger: BudgetLedger, pod: Uuid, dir: &std::path::Path) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                ledger,
                faulted: false,
            })),
            checkpoint: Some((pod, dir.join("budget-consumption.json"))),
        }
    }

    #[cfg(test)]
    pub(crate) fn memory(ledger: BudgetLedger) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                ledger,
                faulted: false,
            })),
            checkpoint: None,
        }
    }

    pub(super) fn restore(
        mut ledger: BudgetLedger,
        pod: Uuid,
        dir: &std::path::Path,
    ) -> Result<Self, &'static str> {
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
                    .record_parent_consumed(Decimal::from_i128_with_scale(
                        i128::from(additional),
                        6,
                    ))
                    .map_err(|_| "budget checkpoint unrepresentable")?;
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
        Ok(Self::new(ledger, pod, dir))
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

    pub(crate) fn available(&self) -> Result<Decimal, String> {
        Ok(self.lock()?.ledger.available())
    }

    pub(super) fn live_children(&self) -> Result<usize, String> {
        Ok(self.lock()?.ledger.live_children())
    }

    pub(super) fn try_allocate(&self, child: u128, amount: Decimal) -> Result<(), String> {
        self.lock()?
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

    /// Serialize affordability, durable evidence, debit and checkpoint against
    /// child admission. No executable permit escapes until both writes succeed.
    /// A failed checkpoint latches refusal; it cannot create spendable credit.
    pub(crate) fn commit<T>(
        &self,
        amount: Decimal,
        evidence: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        let mut state = self.lock()?;
        if amount < Decimal::ZERO
            || amount > state.ledger.available()
            || state.ledger.available() <= Decimal::ZERO
        {
            return Err("host budget exhausted for operator call charge".into());
        }
        let record = evidence()?;
        state
            .ledger
            .record_parent_consumed(amount)
            .map_err(|e| e.to_string())?;
        self.persist(&mut state)?;
        Ok(record)
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
                consumed_micro: state.ledger.core().parent_consumed_units(),
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
