# Gap: `summarize` — portfolio rollup over grade receipts (nucleus-oracle)

Add a pure, deterministic, integer-only function that rolls up a batch of
`GradeReceipt`s (one marketplace round of graded agents) into a portfolio
summary. No float (the crate denies float arithmetic). No panics.

## Types already in nucleus-oracle (public)
```rust
pub struct CountPair { pub matched: u64, pub total: u64 }
pub struct KofN { pub agree: u64, pub n: u64, pub k: u64, pub pinned: bool }
pub enum QuarantineReason { /* unit + struct variants; Display */ }
pub struct GradeReceipt {
    pub submission_id: String,
    pub exact_pass: CountPair,   // DEDUCTIVE, load-bearing
    pub mr: CountPair,           // statistical (carried)
    pub k_of_n: KofN,
    pub mutation: CountPair,     // statistical (carried)
    pub quarantine: Option<QuarantineReason>,
}
impl GradeReceipt { pub fn is_quarantined(&self) -> bool; } // == quarantine.is_some()
```

## The function + type to add (EXACT signatures)
```rust
/// Roll up a batch of grade receipts into a portfolio summary. Quarantined
/// receipts are counted but EXCLUDED from the load-bearing aggregates.
/// Integer-only; deterministic; never panics.
pub fn summarize(receipts: &[GradeReceipt]) -> PortfolioSummary;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortfolioSummary {
    pub submissions: usize,          // receipts.len()
    pub quarantined: usize,          // count is_quarantined()
    pub load_bearing: usize,         // count NOT quarantined
    pub exact_matched: u64,          // sum exact_pass.matched over NON-quarantined
    pub exact_total: u64,            // sum exact_pass.total over NON-quarantined
    pub mean_pass_permille: u32,     // floor(1000*exact_matched/exact_total), 0 if exact_total==0
}
```

## Rules (what the held-out tests check)
1. submissions == receipts.len(); quarantined + load_bearing == submissions.
2. Quarantined receipts contribute NOTHING to exact_matched / exact_total / mean_pass_permille.
3. mean_pass_permille = floor(1000 * exact_matched / exact_total) using u128 intermediate; if exact_total == 0 -> 0.
4. Empty input -> all zeros.
5. No float, no panic, no overflow (u128 intermediates for the permille multiply).

## Test-fixture construction (for the held-out test author)
Integration test using the public API:
```rust
use nucleus_oracle::{summarize, PortfolioSummary, GradeReceipt, CountPair, KofN, QuarantineReason};
fn receipt(id: &str, matched: u64, total: u64, quarantined: bool) -> GradeReceipt {
    GradeReceipt {
        submission_id: id.into(),
        exact_pass: CountPair { matched, total },
        mr: CountPair { matched: 0, total: 0 },
        k_of_n: KofN { agree: 3, n: 3, k: 2, pinned: true },
        mutation: CountPair { matched: 0, total: 0 },
        quarantine: if quarantined { Some(QuarantineReason::HeldOutExpectedLeaked) } else { None },
    }
}
```
`HeldOutExpectedLeaked` is a unit variant (no fields). Quarantined iff quarantine.is_some().
