//! Portfolio rollup over a batch of grade receipts (see `summarize`).
//!
//! Produced by the dogfood coalition: implementer agent wrote `summarize` from a
//! spec only; an independent test-author agent wrote the held-out suite that
//! graded it (tests/summarize_heldout.rs). See docs/dogfood-coalition.md.

use crate::GradeReceipt;

/// Roll up a batch of grade receipts into a portfolio summary. Quarantined
/// receipts are counted but EXCLUDED from the load-bearing aggregates.
/// Integer-only; deterministic; never panics.
///
/// `mean_pass_permille` is `floor(1000 * exact_matched / exact_total)` computed
/// over the non-quarantined receipts using a `u128` intermediate to avoid
/// overflow, and is `0` when `exact_total == 0`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortfolioSummary {
    pub submissions: usize,
    pub quarantined: usize,
    pub load_bearing: usize,
    pub exact_matched: u64,
    pub exact_total: u64,
    pub mean_pass_permille: u32,
}

pub fn summarize(receipts: &[GradeReceipt]) -> PortfolioSummary {
    let submissions = receipts.len();
    let mut quarantined: usize = 0;
    let mut load_bearing: usize = 0;
    let mut exact_matched: u64 = 0;
    let mut exact_total: u64 = 0;

    for r in receipts {
        if r.is_quarantined() {
            quarantined += 1;
        } else {
            load_bearing += 1;
            exact_matched = exact_matched.saturating_add(r.exact_pass.matched);
            exact_total = exact_total.saturating_add(r.exact_pass.total);
        }
    }

    let mean_pass_permille: u32 = if exact_total == 0 {
        0
    } else {
        let scaled = (exact_matched as u128) * 1000u128;
        let permille = scaled / (exact_total as u128);
        // permille is at most 1000 when matched <= total, but clamp defensively
        // so a malformed receipt (matched > total) can never overflow u32.
        if permille > u32::MAX as u128 {
            u32::MAX
        } else {
            permille as u32
        }
    };

    PortfolioSummary {
        submissions,
        quarantined,
        load_bearing,
        exact_matched,
        exact_total,
        mean_pass_permille,
    }
}

impl PortfolioSummary {
    /// Combine two summaries as if both batches had been summarized together.
    pub fn merge(&self, other: &PortfolioSummary) -> PortfolioSummary {
        let exact_matched = self.exact_matched.saturating_add(other.exact_matched);
        let exact_total = self.exact_total.saturating_add(other.exact_total);
        let mean_pass_permille = if exact_total == 0 {
            0
        } else {
            ((1000u128 * exact_matched as u128) / exact_total as u128) as u32
        };
        PortfolioSummary {
            submissions: self.submissions.saturating_add(other.submissions),
            quarantined: self.quarantined.saturating_add(other.quarantined),
            load_bearing: self.load_bearing.saturating_add(other.load_bearing),
            exact_matched,
            exact_total,
            mean_pass_permille,
        }
    }
}
