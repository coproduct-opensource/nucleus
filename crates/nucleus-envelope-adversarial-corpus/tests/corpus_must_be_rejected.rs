//! The load-bearing CI gate: every case in the corpus MUST be
//! rejected by `verify_bundle`. When this test fails on a PR, a
//! security regression has crept in — do not merge until either
//! (a) the bug is fixed, or (b) the case is retracted with an
//! explicit reason recorded in the PR description.

use nucleus_envelope::verify_bundle;
use nucleus_envelope_adversarial_corpus::corpus;

#[test]
fn every_corpus_case_is_rejected() {
    let cases = corpus();
    assert!(
        !cases.is_empty(),
        "corpus must contain at least one case — empty corpus means this gate trivially passes"
    );

    let mut failures: Vec<String> = Vec::new();
    for case in &cases {
        let (bundle, anchor) = (case.build)();
        match verify_bundle(&bundle, &anchor) {
            Ok(report) => {
                failures.push(format!(
                    "{}: BUG — verify_bundle ACCEPTED an adversarial case.\n  \
                     summary: {}\n  \
                     unexpected_report: {:?}",
                    case.name, case.summary, report
                ));
            }
            Err(err) => {
                let dbg = format!("{err:?}");
                if !dbg.contains(case.expected_kind_substr) {
                    failures.push(format!(
                        "{}: rejected (good) but with the wrong variant.\n  \
                         expected substring: {:?}\n  \
                         actual debug: {}",
                        case.name, case.expected_kind_substr, dbg
                    ));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "ADVERSARIAL CORPUS FAILURES ({} of {}):\n\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n\n")
    );
}
