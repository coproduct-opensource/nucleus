//! HELD-OUT integration tests for `nucleus_oracle::summarize`.
//! Authored against CONTRACT.md only; the implementation is unknown to the author.
//! Integer-only, deterministic, no-panic, no-overflow guarantees are exercised here.

use nucleus_oracle::{
    summarize, CountPair, GradeReceipt, KofN, PortfolioSummary, QuarantineReason,
};

/// Fixture per the contract's construction pattern.
fn receipt(id: &str, matched: u64, total: u64, quarantined: bool) -> GradeReceipt {
    GradeReceipt {
        submission_id: id.into(),
        exact_pass: CountPair { matched, total },
        mr: CountPair {
            matched: 0,
            total: 0,
        },
        k_of_n: KofN {
            agree: 3,
            n: 3,
            k: 2,
            pinned: true,
        },
        mutation: CountPair {
            matched: 0,
            total: 0,
        },
        quarantine: if quarantined {
            Some(QuarantineReason::HeldOutExpectedLeaked)
        } else {
            None
        },
    }
}

// ---------------------------------------------------------------------------
// Rule 4: Empty input -> all zeros.
// ---------------------------------------------------------------------------

#[test]
fn empty_input_is_all_zeros() {
    let got = summarize(&[]);
    assert_eq!(
        got,
        PortfolioSummary {
            submissions: 0,
            quarantined: 0,
            load_bearing: 0,
            exact_matched: 0,
            exact_total: 0,
            mean_pass_permille: 0,
        }
    );
}

// ---------------------------------------------------------------------------
// Rule 1: submissions == len; quarantined + load_bearing == submissions.
// ---------------------------------------------------------------------------

#[test]
fn submissions_equals_len() {
    let rs = [
        receipt("a", 1, 2, false),
        receipt("b", 3, 4, true),
        receipt("c", 0, 0, false),
    ];
    let s = summarize(&rs);
    assert_eq!(s.submissions, 3);
}

#[test]
fn quarantined_plus_load_bearing_equals_submissions() {
    let rs = [
        receipt("a", 1, 2, false),
        receipt("b", 3, 4, true),
        receipt("c", 5, 6, true),
        receipt("d", 7, 8, false),
        receipt("e", 9, 10, false),
    ];
    let s = summarize(&rs);
    assert_eq!(s.submissions, 5);
    assert_eq!(s.quarantined, 2);
    assert_eq!(s.load_bearing, 3);
    assert_eq!(s.quarantined + s.load_bearing, s.submissions);
}

#[test]
fn all_quarantined_partition_holds() {
    let rs = [receipt("a", 1, 2, true), receipt("b", 3, 4, true)];
    let s = summarize(&rs);
    assert_eq!(s.submissions, 2);
    assert_eq!(s.quarantined, 2);
    assert_eq!(s.load_bearing, 0);
    assert_eq!(s.quarantined + s.load_bearing, s.submissions);
}

#[test]
fn none_quarantined_partition_holds() {
    let rs = [receipt("a", 1, 2, false), receipt("b", 3, 4, false)];
    let s = summarize(&rs);
    assert_eq!(s.submissions, 2);
    assert_eq!(s.quarantined, 0);
    assert_eq!(s.load_bearing, 2);
    assert_eq!(s.quarantined + s.load_bearing, s.submissions);
}

// ---------------------------------------------------------------------------
// Rule 2: Quarantined receipts contribute NOTHING to the load-bearing aggregates.
// ---------------------------------------------------------------------------

#[test]
fn quarantined_excluded_from_exact_sums() {
    // Non-quarantined: matched 2+3=5, total 4+6=10.
    // Quarantined entries carry large values that must be ignored entirely.
    let rs = [
        receipt("keep1", 2, 4, false),
        receipt("drop1", 1_000_000, 1_000_000, true),
        receipt("keep2", 3, 6, false),
        receipt("drop2", 999, 999, true),
    ];
    let s = summarize(&rs);
    assert_eq!(s.exact_matched, 5);
    assert_eq!(s.exact_total, 10);
    // floor(1000 * 5 / 10) = 500
    assert_eq!(s.mean_pass_permille, 500);
}

#[test]
fn quarantined_only_yields_zero_aggregates_but_counts() {
    let rs = [receipt("q1", 7, 9, true), receipt("q2", 11, 13, true)];
    let s = summarize(&rs);
    assert_eq!(s.exact_matched, 0);
    assert_eq!(s.exact_total, 0);
    assert_eq!(s.mean_pass_permille, 0);
    assert_eq!(s.submissions, 2);
    assert_eq!(s.quarantined, 2);
}

// ---------------------------------------------------------------------------
// Rule 3: mean_pass_permille = floor(1000 * matched / total); 0 if total == 0.
// ---------------------------------------------------------------------------

#[test]
fn permille_exact_half() {
    let rs = [receipt("a", 1, 2, false)];
    let s = summarize(&rs);
    assert_eq!(s.exact_matched, 1);
    assert_eq!(s.exact_total, 2);
    assert_eq!(s.mean_pass_permille, 500);
}

#[test]
fn permille_full_pass() {
    let rs = [receipt("a", 10, 10, false)];
    let s = summarize(&rs);
    assert_eq!(s.mean_pass_permille, 1000);
}

#[test]
fn permille_zero_matched() {
    let rs = [receipt("a", 0, 10, false)];
    let s = summarize(&rs);
    assert_eq!(s.mean_pass_permille, 0);
}

#[test]
fn permille_floor_truncates() {
    // 1000 * 1 / 3 = 333.33... -> floor 333
    let rs = [receipt("a", 1, 3, false)];
    let s = summarize(&rs);
    assert_eq!(s.exact_matched, 1);
    assert_eq!(s.exact_total, 3);
    assert_eq!(s.mean_pass_permille, 333);
}

#[test]
fn permille_floor_truncates_two_thirds() {
    // 1000 * 2 / 3 = 666.66... -> floor 666
    let rs = [receipt("a", 2, 3, false)];
    let s = summarize(&rs);
    assert_eq!(s.mean_pass_permille, 666);
}

#[test]
fn permille_aggregated_across_receipts() {
    // matched 1+2+3 = 6, total 4+5+6 = 15 -> 1000*6/15 = 400
    let rs = [
        receipt("a", 1, 4, false),
        receipt("b", 2, 5, false),
        receipt("c", 3, 6, false),
    ];
    let s = summarize(&rs);
    assert_eq!(s.exact_matched, 6);
    assert_eq!(s.exact_total, 15);
    assert_eq!(s.mean_pass_permille, 400);
}

#[test]
fn permille_zero_when_total_zero_nonempty() {
    // Non-quarantined but with zero totals -> exact_total == 0 -> permille 0 (no div-by-zero panic).
    let rs = [receipt("a", 0, 0, false), receipt("b", 0, 0, false)];
    let s = summarize(&rs);
    assert_eq!(s.exact_matched, 0);
    assert_eq!(s.exact_total, 0);
    assert_eq!(s.mean_pass_permille, 0);
}

#[test]
fn permille_matched_can_exceed_total_no_panic() {
    // Pathological data (matched > total). Must not panic; floor formula still applies.
    // 1000 * 5 / 2 = 2500
    let rs = [receipt("a", 5, 2, false)];
    let s = summarize(&rs);
    assert_eq!(s.exact_matched, 5);
    assert_eq!(s.exact_total, 2);
    assert_eq!(s.mean_pass_permille, 2500);
}

// ---------------------------------------------------------------------------
// Rule 5: No overflow — u128 intermediate for the permille multiply.
// 1000 * exact_matched would overflow u64 if matched is near u64::MAX.
// ---------------------------------------------------------------------------

#[test]
fn large_values_require_u128_intermediate() {
    // matched ~ u64::MAX / 2; 1000 * matched overflows u64 (>1.8e19 ceiling)
    // but fits comfortably in u128. Expected permille = floor(1000*matched/total).
    let matched: u64 = u64::MAX / 2; // 9_223_372_036_854_775_807
    let total: u64 = u64::MAX; //       18_446_744_073_709_551_615
    let rs = [receipt("big", matched, total, false)];
    let s = summarize(&rs);

    let expected: u32 = ((1000u128 * matched as u128) / total as u128) as u32;
    // Sanity: this is ~499 (just under half).
    assert_eq!(expected, 499);
    assert_eq!(s.exact_matched, matched);
    assert_eq!(s.exact_total, total);
    assert_eq!(s.mean_pass_permille, expected);
}

#[test]
fn large_full_pass_does_not_overflow() {
    // matched == total == u64::MAX. 1000 * u64::MAX overflows u64; with u128 -> exactly 1000.
    let big = u64::MAX;
    let rs = [receipt("a", big, big, false)];
    let s = summarize(&rs);
    assert_eq!(s.exact_matched, big);
    assert_eq!(s.exact_total, big);
    assert_eq!(s.mean_pass_permille, 1000);
}

#[test]
fn summing_many_large_receipts_no_overflow_in_aggregate() {
    // Several receipts whose totals each are large but whose sum still fits in u64.
    // matched sum = 3 * (u64::MAX/6), total sum = 3 * (u64::MAX/6) ... keep within u64.
    let unit = u64::MAX / 6;
    let rs = [
        receipt("a", unit, unit, false),
        receipt("b", unit, unit, false),
        receipt("c", unit, unit, false),
    ];
    let s = summarize(&rs);
    assert_eq!(s.exact_matched, unit * 3);
    assert_eq!(s.exact_total, unit * 3);
    // Full pass -> 1000.
    assert_eq!(s.mean_pass_permille, 1000);
}

// ---------------------------------------------------------------------------
// Combined / determinism.
// ---------------------------------------------------------------------------

#[test]
fn full_combined_summary_is_exact() {
    let rs = [
        receipt("keep1", 3, 10, false), // counts
        receipt("q1", 100, 100, true),  // excluded from aggregates
        receipt("keep2", 5, 10, false), // counts
        receipt("keep3", 0, 0, false),  // counts, contributes 0/0
        receipt("q2", 50, 50, true),    // excluded
    ];
    let s = summarize(&rs);
    assert_eq!(
        s,
        PortfolioSummary {
            submissions: 5,
            quarantined: 2,
            load_bearing: 3,
            exact_matched: 8,        // 3 + 5
            exact_total: 20,         // 10 + 10 + 0
            mean_pass_permille: 400, // 1000 * 8 / 20
        }
    );
}

#[test]
fn deterministic_repeated_calls() {
    let rs = [
        receipt("a", 1, 3, false),
        receipt("b", 2, 7, true),
        receipt("c", 4, 9, false),
    ];
    let a = summarize(&rs);
    let b = summarize(&rs);
    assert_eq!(a, b);
}
