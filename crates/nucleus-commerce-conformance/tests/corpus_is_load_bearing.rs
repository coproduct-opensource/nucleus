//! The corpus's own gate.
//!
//! Two things are checked here, and the second matters more than the first.

use nucleus_commerce_conformance::{
    corpus, corpus_covers_both_directions, evaluate, export_vectors, Expect, Property,
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
        if let Some(want) = case.expect_reason_contains {
            if !reason.contains(want) {
                wrong.push(format!(
                    "  {}: verdict right but reason wrong — expected it to mention `{want}`, got {reason}",
                    case.name
                ));
            }
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
