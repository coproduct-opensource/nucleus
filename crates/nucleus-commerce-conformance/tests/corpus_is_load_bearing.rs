//! The corpus's own gate.
//!
//! Two things are checked here, and the second matters more than the first.

use nucleus_commerce_conformance::{
    Expect, Property, corpus, corpus_covers_both_directions, evaluate, export_vectors,
};

/// Nucleus's own implementation must reach every case's required verdict. If
/// this fails, either the corpus is wrong or nucleus is — and the corpus is the
/// thing integrators are being asked to match, so it cannot quietly disagree
/// with the reference.
#[test]
fn nucleus_itself_conforms() {
    let mut wrong = Vec::new();
    for case in corpus() {
        let (got, reason) = evaluate(&case.input);
        if got != case.expect {
            wrong.push(format!(
                "  {} ({}): expected {:?}, nucleus said {:?}",
                case.name, case.summary, case.expect, got
            ));
            continue;
        }
        // Where the verdict alone cannot distinguish conforming from broken,
        // the reason is pinned too.
        if let Some(want) = case.expect_reason_contains
            && !reason.contains(want)
        {
            wrong.push(format!(
                    "  {}: verdict right but reason wrong — expected it to mention `{want}`, got {reason}",
                    case.name
                ));
        }
    }
    assert!(
        wrong.is_empty(),
        "nucleus does not conform to its own corpus:\n{}",
        wrong.join("\n")
    );
}

/// **The anti-vacuity gate.** An attack-only corpus is passed in full by an
/// implementation that rejects everything: perfect security, zero function, full
/// marks. Every property must therefore carry cases in both directions, so a
/// conforming runtime has to say yes to the honest case AND no to the attack.
#[test]
fn every_property_has_cases_in_both_directions() {
    let missing = corpus_covers_both_directions();
    assert!(
        missing.is_empty(),
        "a corpus an implementation could pass by always answering the same way: {missing:?}"
    );
}

/// The two trivial implementations must both fail. This is the anti-vacuity
/// guard's own bite: if either passes, the corpus is not discriminating.
#[test]
fn always_accept_and_always_reject_both_fail_the_corpus() {
    let cases = corpus();

    let always_accept_wrong = cases.iter().filter(|c| c.expect == Expect::Reject).count();
    let always_reject_wrong = cases.iter().filter(|c| c.expect == Expect::Accept).count();

    assert!(
        always_accept_wrong > 0,
        "an implementation that accepts everything must fail somewhere"
    );
    assert!(
        always_reject_wrong > 0,
        "an implementation that rejects everything must fail somewhere"
    );
}

/// Every property is actually exercised — a property with no cases is a claim
/// the corpus does not check.
#[test]
fn every_property_is_exercised() {
    let cases = corpus();
    for p in Property::all() {
        assert!(
            cases.iter().any(|c| c.property == p),
            "{p:?} has no cases — the corpus claims coverage it does not have"
        );
    }
}

/// A case that pins a reason must exist for the disclosure property, because a
/// mutation test showed the verdict alone cannot detect disclosure enforcement
/// being deleted: sponsored content is adversarial, so the trifecta denies the
/// flow either way. Without a reason-pinned case, `DisclosureRequired` is a
/// property the corpus claims to check and does not.
#[test]
fn the_disclosure_property_is_pinned_by_reason_not_just_verdict() {
    let pinned = corpus()
        .into_iter()
        .filter(|c| c.property == Property::DisclosureRequired)
        .filter(|c| c.expect_reason_contains.is_some())
        .count();
    assert!(
        pinned >= 2,
        "disclosure needs reason-pinned cases in both directions, found {pinned}"
    );
}

/// Case names are unique, so a conformance report can cite one unambiguously.
#[test]
fn case_names_are_unique() {
    let cases = corpus();
    let mut names: Vec<_> = cases.iter().map(|c| c.name).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(before, names.len(), "duplicate case name in the corpus");
}

/// The exported vectors are what a non-Rust runtime consumes, so they must be
/// valid JSON with every case present and self-describing.
#[test]
fn the_exported_vectors_are_complete_and_parseable() {
    let json = export_vectors();
    let v: serde_json::Value = serde_json::from_str(&json).expect("vectors are valid JSON");
    let arr = v["cases"].as_array().expect("cases is an array");
    assert_eq!(arr.len(), corpus().len(), "every case is exported");
    for c in arr {
        for field in ["name", "summary", "property", "expect", "input"] {
            assert!(
                c.get(field).is_some(),
                "exported case is missing `{field}` — a consumer cannot use it"
            );
        }
    }
}

/// **The corpus must keep exercising integer-division dust.**
///
/// `route_to_commons` assigns the remainder to the FIRST share. Every original
/// vector divided evenly, so nothing revealed that rule — and an independent
/// implementation written from those vectors truncates, passes the whole corpus,
/// and then skims one micro-USD per split forever, blessed by its own verifier.
/// Demonstrated, not hypothesised: `examples/independent-conformance/conform.py`
/// with the dust rule removed passes the 14-case corpus and fails this one.
///
/// So at least one payout vector must have a split that does NOT divide evenly.
/// If someone later "tidies" the corpus to round numbers, this reds.
#[test]
fn a_payout_vector_exercises_integer_division_dust() {
    use nucleus_commerce_conformance::{CaseInput, corpus};

    let dusty = corpus().into_iter().any(|c| {
        let CaseInput::Payout(p) = &c.input else {
            return false;
        };
        let nucleus_recompute::ClearingReceipt::Settlement(s) = &p.clearing else {
            return false;
        };
        let pool = u128::from(s.price_micro) * u128::from(s.delivered_bps.min(10_000)) / 10_000;
        // Dust exists when at least one share does not divide the pool exactly.
        p.shares
            .iter()
            .any(|sh| pool * u128::from(sh.bps) % 10_000 != 0)
    });

    assert!(
        dusty,
        "no payout vector has a remainder — an implementation that truncates instead of \
         assigning the dust would pass this corpus and then skim on every real split"
    );
}

/// #2736: the checked-in corpus must be what the generator emits.
///
/// `examples/independent-conformance/vectors.json` is generated output —
/// `cargo run --example vectors` — committed so a third-party implementation can
/// read it without a Rust toolchain. Generated output under version control
/// goes stale silently, and this one went stale invisibly twice over: nothing
/// regenerated it, and nothing compared it.
///
/// A stale corpus is worse than no corpus. `conform.py` would keep passing while
/// validating an independent implementation against a spec nucleus has moved
/// past — certifying conformance to something nobody enforces. When #2359 grew
/// the corpus 14 -> 16, only luck kept the file current.
///
/// This lives here rather than in `ci/` on purpose: it guards the relationship
/// between `export_vectors()` and one file, so it belongs next to
/// `export_vectors()`, where a change to the generator sees it fail immediately.
#[test]
fn the_checked_in_vectors_are_what_the_generator_emits() {
    // `examples/vectors.rs` is `println!("{}", export_vectors())`, so the file on
    // disk is that string plus the newline `println!` adds.
    let generated = nucleus_commerce_conformance::export_vectors();
    let checked_in = include_str!("../../../examples/independent-conformance/vectors.json");

    assert_eq!(
        generated.trim_end(),
        checked_in.trim_end(),
        "examples/independent-conformance/vectors.json is stale.\n\
         Regenerate it:\n  \
         cargo run -q -p nucleus-commerce-conformance --example vectors \
         > examples/independent-conformance/vectors.json\n\
         Do NOT hand-edit it, and do not delete this test to get green — a \
         third-party implementation is checking itself against that file."
    );

    // Non-vacuity: both sides must be a real corpus. A generator that returned
    // "" against an empty file would satisfy the assert above while proving
    // nothing, which is the failure shape this whole test exists to catch.
    let parsed: serde_json::Value =
        serde_json::from_str(checked_in).expect("the checked-in corpus must be JSON");
    let cases = parsed["cases"]
        .as_array()
        .expect("the corpus must carry a `cases` array");
    assert!(
        cases.len() >= 16,
        "expected at least the 16 cases #2359 established, found {}",
        cases.len()
    );
}
