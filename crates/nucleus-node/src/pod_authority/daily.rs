//! A binding's allocations per UTC day, for `max_cost_usd_per_day`.
//!
//! The day dimension sits BESIDE the ledger, never in place of it: an
//! admission must fit the binding's ledger (`budget conservation`, the whole
//! life's ceiling) AND, when the binding sets one, what is left of today's
//! allowance. A new UTC day starts with nothing charged, so a binding whose
//! allowance ran out admits again at midnight UTC with no restart.
//!
//! What a day is charged: a pod's allocation, at admission, to the UTC day of
//! the admission. An allocation that is handed back because the pod never ran
//! (an unspawned reservation, or an admission refused after reserving) is
//! credited to the day it was charged to, whatever day it is now. A pod that
//! ran keeps its charge: the ledger folds its whole allocation into
//! consumption (`ReleaseKind::Exited`), and the day agrees with it.
//!
//! Persisted beside the ledger in `authority/external/<key>.json` as
//! `days = { "YYYY-MM-DD": micro-USD }`. Days more than [`DAY_HISTORY`] before
//! the latest charged day are dropped when written: they bound nothing, and the
//! ledger's `consumed_micro` is the history of what was spent.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use chrono::NaiveDate;
use uuid::Uuid;

/// Days kept in the persisted record, counting back from the latest charged.
pub(super) const DAY_HISTORY: i64 = 35;

/// Today's UTC date. Injectable so a test can turn the day over.
pub(crate) type DayClock = Arc<dyn Fn() -> NaiveDate + Send + Sync>;

pub(super) fn utc_today() -> DayClock {
    Arc::new(|| chrono::Utc::now().date_naive())
}

/// Per-day charges for one binding's ledger.
#[derive(Debug, Default)]
pub(super) struct Days {
    charged: BTreeMap<NaiveDate, u64>,
    /// Pods whose charge could still be credited back: admitted, not yet
    /// released. In memory only, because only an in-process reservation can
    /// be credited, and none survives a restart.
    live: HashMap<Uuid, (NaiveDate, u64)>,
}

impl Days {
    /// What `day` has been charged, in micro-USD.
    pub(super) fn charged(&self, day: NaiveDate) -> u64 {
        self.charged.get(&day).copied().unwrap_or(0)
    }

    /// Charge `micro` to `day` for `pod`.
    pub(super) fn charge(&mut self, pod: Uuid, day: NaiveDate, micro: u64) {
        let total = self.charged.entry(day).or_insert(0);
        *total = total.saturating_add(micro);
        self.live.insert(pod, (day, micro));
    }

    /// `pod` never ran: credit its charge to the day it was charged to.
    pub(super) fn refund(&mut self, pod: Uuid) {
        if let Some((day, micro)) = self.live.remove(&pod)
            && let Some(total) = self.charged.get_mut(&day)
        {
            *total = total.saturating_sub(micro);
        }
    }

    /// `pod` ran and was released: its charge stands.
    pub(super) fn settle(&mut self, pod: Uuid) {
        self.live.remove(&pod);
    }

    /// The persisted form, keeping [`DAY_HISTORY`] days back from the latest.
    pub(super) fn record(&self) -> BTreeMap<String, u64> {
        let Some(latest) = self.charged.keys().next_back().copied() else {
            return BTreeMap::new();
        };
        let oldest = latest - chrono::Duration::days(DAY_HISTORY);
        self.charged
            .range(oldest..)
            .map(|(day, micro)| (day.format("%Y-%m-%d").to_string(), *micro))
            .collect()
    }

    /// From the persisted form. A key that is not a date refuses the whole
    /// record, as any other unreadable ledger field does.
    pub(super) fn restore(record: BTreeMap<String, u64>) -> Option<Self> {
        let mut charged = BTreeMap::new();
        for (day, micro) in record {
            charged.insert(NaiveDate::parse_from_str(&day, "%Y-%m-%d").ok()?, micro);
        }
        Some(Self {
            charged,
            live: HashMap::new(),
        })
    }
}
