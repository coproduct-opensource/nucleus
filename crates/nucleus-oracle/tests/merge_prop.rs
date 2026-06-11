//! Algebraic-law / metamorphic test suite for `PortfolioSummary::merge`.
//!
//! These tests are deliberately distinct from example-based tests: they assert
//! the MONOID laws (closure via the metamorphic relation, associativity,
//! commutativity, identity) rather than specific numeric outputs. The key
//! invariant is the metamorphic law from CONTRACT.md:
//!
//!   summarize(&[a, b].concat()) == summarize(a).merge(&summarize(b))
//!
//! If that holds for arbitrary batches, then merge faithfully reconstructs the
//! summary of the concatenation, and associativity/commutativity follow from
//! the corresponding properties of `concat` on receipt batches.

use nucleus_oracle::{
    summarize, CountPair, GradeReceipt, KofN, PortfolioSummary, QuarantineReason,
};

/// Contract fixture (verbatim from CONTRACT.md).
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

/// A spread of receipt batches exercising the corners that matter for the
/// permille recomputation: empty, all-zero totals, partial matches, fully
/// matched, quarantined entries, and lopsided totals between batches.
fn batches() -> Vec<Vec<GradeReceipt>> {
    vec![
        // empty batch (drives the identity / exact_total == 0 corner)
        vec![],
        // single zero-total receipt: contributes a submission but no exact pairs
        vec![receipt("z0", 0, 0, false)],
        // partial matches
        vec![receipt("p0", 1, 2, false), receipt("p1", 3, 4, false)],
        // fully matched
        vec![receipt("f0", 5, 5, false), receipt("f1", 7, 7, false)],
        // none matched but with totals (pulls the mean down)
        vec![receipt("n0", 0, 9, false)],
        // quarantined entries mixed with passing ones
        vec![
            receipt("q0", 2, 3, true),
            receipt("q1", 4, 4, false),
            receipt("q2", 0, 0, true),
        ],
        // lopsided large totals: ensures permille is recomputed from totals,
        // not averaged across the two input permilles
        vec![
            receipt("L0", 1, 1000, false),
            receipt("L1", 999, 1000, false),
        ],
        // many small partials
        (0..6)
            .map(|i| receipt(&format!("m{i}"), i as u64, 5, i % 2 == 0))
            .collect(),
    ]
}

/// THE metamorphic law: merging shard summaries equals summarizing the
/// concatenation of the underlying receipt batches. Asserted across every
/// ordered pair of fixture batches.
#[test]
fn metamorphic_merge_equals_summarize_concat() {
    let bs = batches();
    for a in &bs {
        for b in &bs {
            let concat: Vec<GradeReceipt> = a.iter().cloned().chain(b.iter().cloned()).collect();

            let whole = summarize(&concat);
            let merged = summarize(a).merge(&summarize(b));

            assert_eq!(
                whole,
                merged,
                "metamorphic law violated for batches of len {} and {}",
                a.len(),
                b.len()
            );
        }
    }
}

/// Commutativity: a.merge(&b) == b.merge(&a) for all shard summaries.
#[test]
fn merge_is_commutative() {
    let summaries: Vec<PortfolioSummary> = batches().iter().map(|b| summarize(b)).collect();
    for a in &summaries {
        for b in &summaries {
            assert_eq!(a.merge(b), b.merge(a), "merge is not commutative");
        }
    }
}

/// Associativity: (a.merge(b)).merge(c) == a.merge(b.merge(c)).
#[test]
fn merge_is_associative() {
    let summaries: Vec<PortfolioSummary> = batches().iter().map(|b| summarize(b)).collect();
    for a in &summaries {
        for b in &summaries {
            for c in &summaries {
                let left = a.merge(b).merge(c);
                let right = a.merge(&b.merge(c));
                assert_eq!(left, right, "merge is not associative");
            }
        }
    }
}

/// Identity: the default (all-zero) summary is a two-sided identity for merge.
#[test]
fn default_is_two_sided_identity() {
    let id = PortfolioSummary::default();
    for b in batches() {
        let a = summarize(&b);
        assert_eq!(a.merge(&id), a, "default is not a right identity");
        assert_eq!(id.merge(&a), a, "default is not a left identity");
    }
}

/// The default summary is itself the summary of an empty batch, and merging two
/// defaults stays the default — a sanity anchor for the identity element.
#[test]
fn default_matches_empty_summary_and_is_idempotent_under_self_merge() {
    let id = PortfolioSummary::default();
    assert_eq!(
        summarize(&[]),
        id,
        "summarize(&[]) should equal the identity"
    );
    assert_eq!(
        id.merge(&id),
        id,
        "merging two identities should stay identity"
    );
}

/// Permille must be RECOMPUTED from merged totals, not averaged. This catches
/// the specific wrong implementation called out in the contract: pick two
/// batches whose individual permilles average to something different from the
/// permille of their pooled totals.
#[test]
fn permille_recomputed_not_averaged() {
    // Batch a: 1/1000  -> permille 1
    // Batch b: 999/1000 -> permille 999
    // Averaging the permilles would give 500; the correct pooled value is
    // floor(1000 * 1000 / 2000) = 500 here, so to make the distinction sharp
    // use asymmetric totals.
    let a = summarize(&[receipt("a0", 1, 10, false)]); // 100 permille
    let b = summarize(&[receipt("b0", 990, 1000, false)]); // 990 permille
                                                           // averaged permille would be 545; pooled = floor(1000*991/1010) = 981.
    let merged = a.merge(&b);
    let pooled = summarize(&[receipt("a0", 1, 10, false), receipt("b0", 990, 1000, false)]);
    assert_eq!(
        merged, pooled,
        "merge must recompute permille from pooled totals"
    );
    assert_eq!(
        merged.mean_pass_permille, 981,
        "expected floor(1000*991/1010) = 981, got {}",
        merged.mean_pass_permille
    );
}
