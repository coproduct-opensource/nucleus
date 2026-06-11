//! Example-based functional tests for `PortfolioSummary::merge`.
//!
//! These are concrete, hand-computed cases — distinct from the property-based
//! suite. Each asserts exact expected field values so a regression points
//! straight at the broken rule.

use nucleus_oracle::{
    summarize, CountPair, GradeReceipt, KofN, PortfolioSummary, QuarantineReason,
};

// Contract fixture: build a receipt with a chosen exact-pass count pair.
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

// Construct a summary directly by field. `mean_pass_permille` is derived so the
// input is internally consistent (floor(1000*matched/total), 0 if total==0).
fn summary(
    submissions: usize,
    quarantined: usize,
    load_bearing: usize,
    exact_matched: u64,
    exact_total: u64,
) -> PortfolioSummary {
    let permille = if exact_total == 0 {
        0
    } else {
        ((1000u128 * exact_matched as u128) / exact_total as u128) as u32
    };
    PortfolioSummary {
        submissions,
        quarantined,
        load_bearing,
        exact_matched,
        exact_total,
        mean_pass_permille: permille,
    }
}

#[test]
fn merge_sums_each_count_field() {
    let a = summary(3, 1, 2, 40, 80);
    let b = summary(5, 2, 1, 10, 20);
    let m = a.merge(&b);

    assert_eq!(m.submissions, 8);
    assert_eq!(m.quarantined, 3);
    assert_eq!(m.load_bearing, 3);
    assert_eq!(m.exact_matched, 50);
    assert_eq!(m.exact_total, 100);
}

#[test]
fn merge_recomputes_permille_from_merged_totals() {
    // a: 40/80 -> 500 permille.  b: 10/20 -> 500 permille.
    // Merged: 50/100 -> floor(1000*50/100) = 500.  (Here averaging happens to
    // agree; the next test forces a case where it does NOT.)
    let a = summary(1, 0, 0, 40, 80);
    let b = summary(1, 0, 0, 10, 20);
    let m = a.merge(&b);
    assert_eq!(m.mean_pass_permille, 500);
}

#[test]
fn merge_permille_is_not_the_average_of_input_permilles() {
    // a: 1/1   -> permille 1000.
    // b: 0/99  -> permille 0.
    // Averaging the two input permilles: (1000 + 0) / 2 = 500  <-- WRONG.
    // Correct, recomputed from merged totals: 1/100 -> floor(1000*1/100) = 10.
    let a = summary(1, 0, 0, 1, 1);
    let b = summary(1, 0, 0, 0, 99);
    assert_eq!(a.mean_pass_permille, 1000);
    assert_eq!(b.mean_pass_permille, 0);

    let m = a.merge(&b);
    assert_eq!(m.exact_matched, 1);
    assert_eq!(m.exact_total, 100);
    assert_eq!(m.mean_pass_permille, 10, "must recompute, not average");
    assert_ne!(
        m.mean_pass_permille, 500,
        "averaging would give the wrong 500"
    );
}

#[test]
fn merge_permille_zero_when_merged_total_is_zero() {
    let a = summary(2, 1, 0, 0, 0);
    let b = summary(3, 0, 0, 0, 0);
    let m = a.merge(&b);
    assert_eq!(m.exact_total, 0);
    assert_eq!(m.mean_pass_permille, 0);
}

#[test]
fn merge_with_default_is_identity_right() {
    let a = summary(7, 2, 4, 123, 456);
    let m = a.merge(&PortfolioSummary::default());
    assert_eq!(m.submissions, a.submissions);
    assert_eq!(m.quarantined, a.quarantined);
    assert_eq!(m.load_bearing, a.load_bearing);
    assert_eq!(m.exact_matched, a.exact_matched);
    assert_eq!(m.exact_total, a.exact_total);
    assert_eq!(m.mean_pass_permille, a.mean_pass_permille);
}

#[test]
fn merge_with_default_is_identity_left() {
    let a = summary(7, 2, 4, 123, 456);
    let m = PortfolioSummary::default().merge(&a);
    assert_eq!(m.submissions, a.submissions);
    assert_eq!(m.quarantined, a.quarantined);
    assert_eq!(m.load_bearing, a.load_bearing);
    assert_eq!(m.exact_matched, a.exact_matched);
    assert_eq!(m.exact_total, a.exact_total);
    assert_eq!(m.mean_pass_permille, a.mean_pass_permille);
}

#[test]
fn merge_default_with_default_is_default() {
    let m = PortfolioSummary::default().merge(&PortfolioSummary::default());
    assert_eq!(m, PortfolioSummary::default());
}

#[test]
fn merge_saturates_counts_instead_of_overflowing() {
    // usize fields near their ceiling: saturating add must clamp, not panic/wrap.
    let a = summary(usize::MAX, usize::MAX, usize::MAX, 0, 0);
    let b = summary(10, 10, 10, 0, 0);
    let m = a.merge(&b);
    assert_eq!(m.submissions, usize::MAX);
    assert_eq!(m.quarantined, usize::MAX);
    assert_eq!(m.load_bearing, usize::MAX);
}

#[test]
fn merge_saturates_u64_totals() {
    let a = summary(0, 0, 0, u64::MAX, u64::MAX);
    let b = summary(0, 0, 0, 5, 5);
    let m = a.merge(&b);
    assert_eq!(m.exact_matched, u64::MAX);
    assert_eq!(m.exact_total, u64::MAX);
    // matched == total -> 1000 permille, computed via u128 without overflow.
    assert_eq!(m.mean_pass_permille, 1000);
}

#[test]
fn merge_large_permille_uses_u128_intermediate() {
    // 1000 * u64::MAX overflows u64; the u128 intermediate must handle it.
    // matched = u64::MAX/2, total = u64::MAX -> ~500 permille.
    let half = u64::MAX / 2;
    let a = summary(0, 0, 0, half, u64::MAX);
    let m = a.merge(&PortfolioSummary::default());
    let expected = ((1000u128 * half as u128) / u64::MAX as u128) as u32;
    assert_eq!(m.mean_pass_permille, expected);
    assert_eq!(expected, 499);
}

#[test]
fn merge_matches_summarize_of_concatenation() {
    // The contract's metamorphic law on concrete batches.
    let a_batch = [receipt("a1", 3, 4, false), receipt("a2", 1, 4, true)];
    let b_batch = [receipt("b1", 5, 5, false), receipt("b2", 0, 6, false)];

    let concat: Vec<GradeReceipt> = a_batch
        .iter()
        .cloned()
        .chain(b_batch.iter().cloned())
        .collect();
    let whole = summarize(&concat);
    let merged = summarize(&a_batch).merge(&summarize(&b_batch));

    assert_eq!(whole, merged);
}

#[test]
fn merge_is_commutative_on_examples() {
    let a = summary(2, 1, 1, 7, 13);
    let b = summary(5, 0, 3, 4, 9);
    assert_eq!(a.merge(&b), b.merge(&a));
}

#[test]
fn merge_is_associative_on_examples() {
    let a = summary(2, 1, 1, 7, 13);
    let b = summary(5, 0, 3, 4, 9);
    let c = summary(1, 1, 0, 2, 2);
    assert_eq!(a.merge(&b).merge(&c), a.merge(&b.merge(&c)));
}
