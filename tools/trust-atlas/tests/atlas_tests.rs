//! Spike acceptance tests:
//! 1. lattice merge is the meet (min behavior through the egglog program);
//! 2. the unenforced-gate rule fires on the checked-in fixture;
//! 3. equivalence transport: after (union a b), a maturity fact asserted on
//!    'a' is retrievable querying 'b' — the egglog-vs-ascent differentiator.

use trust_atlas::atlas::Atlas;
use trust_atlas::model::{Fixtures, Maturity};
use trust_atlas::report;

const CITE: &str = "tests/atlas_tests.rs (synthetic fact)";

#[test]
fn lattice_merge_is_the_meet() {
    let mut atlas = Atlas::new().unwrap();
    // Assert the same artifact at ranks 4, then 2, then 3: min-merge must
    // resolve to 2 — re-asserting a HIGHER rank later cannot relax it.
    atlas
        .set_maturity("artifact", Maturity::ParityPinned, CITE)
        .unwrap();
    atlas
        .set_maturity("artifact", Maturity::Attested, CITE)
        .unwrap();
    atlas
        .set_maturity("artifact", Maturity::PropertyTested, CITE)
        .unwrap();
    assert_eq!(atlas.maturity("artifact"), Some(Maturity::Attested));
}

#[test]
fn path_maturity_is_min_along_the_chain() {
    let mut atlas = Atlas::new().unwrap();
    atlas
        .set_edge("a", "b", Maturity::KernelChecked, CITE)
        .unwrap();
    atlas.set_edge("b", "c", Maturity::Stated, CITE).unwrap();
    atlas
        .set_edge("c", "d", Maturity::ParityPinned, CITE)
        .unwrap();
    atlas.saturate().unwrap();
    assert_eq!(atlas.path_maturity("a", "d"), Some(Maturity::Stated));
    // prefix is unaffected by the weak tail edge
    assert_eq!(atlas.path_maturity("a", "b"), Some(Maturity::KernelChecked));
}

#[test]
fn unenforced_gate_rule_fires_on_the_fixture() {
    let fixtures = Fixtures::load(&Fixtures::default_dir()).unwrap();
    // Fixture-only (no_live): deterministic in CI.
    let gates = report::gate_findings(&fixtures, false).unwrap();

    // The recon ground truth: CodeQL runs on PR but is not a required check…
    assert!(gates
        .unenforced
        .iter()
        .any(|(repo, name)| repo.starts_with("coproduct-opensource/nucleus") && name == "CodeQL"));
    // …as is every formal-proof gate, e.g. the Lean kernel proof and Kani BMC.
    assert!(gates
        .unenforced
        .iter()
        .any(|(_, name)| name == "Lean 4 Kernel Proof"));
    assert!(gates.unenforced.iter().any(|(_, name)| name == "Kani BMC"));
    // The enforced ones must NOT fire: CI (fmt/clippy/test) and Security Audit.
    assert!(!gates.unenforced.iter().any(|(_, name)| name == "CI"));
    assert!(!gates
        .unenforced
        .iter()
        .any(|(_, name)| name == "Security Audit"));
    // spiffy has zero required checks: its Lean gate is unenforced too.
    assert!(gates
        .unenforced
        .iter()
        .any(|(repo, name)| repo.starts_with("coproduct-private/spiffy")
            && name == "Lean formal proofs"));
    // And the rule itself (not Rust filtering) is what derived these.
    let mut atlas = gates.atlas;
    assert!(atlas
        .is_unenforced("coproduct-opensource/nucleus (/Users/bcrisp/coproduct/nucleus) :: CodeQL"));
    assert!(!atlas
        .is_unenforced("coproduct-opensource/nucleus (/Users/bcrisp/coproduct/nucleus) :: CI"));
}

#[test]
fn equivalence_transport_makes_facts_queryable_from_the_other_side() {
    let mut atlas = Atlas::new().unwrap();
    // Union FIRST, assert on 'a' only, query via 'b': congruence must answer.
    atlas
        .add_equivalence("a == b", "a", "b", Maturity::ParityPinned, "", CITE)
        .unwrap();
    // add_equivalence asserts the equivalence rank on the class; now assert a
    // *different* fact about 'a' and read it back through 'b'.
    atlas
        .set_maturity("a", Maturity::PropertyTested, CITE)
        .unwrap();
    atlas.saturate().unwrap();
    assert_eq!(atlas.maturity("b"), Some(Maturity::PropertyTested));
}

#[test]
fn equivalence_transport_min_merges_across_the_union() {
    let mut atlas = Atlas::new().unwrap();
    // Both sides carry maturity BEFORE the union; the unioned class must
    // resolve to the meet (weakest side), mirroring attenuation.
    atlas
        .set_maturity("x", Maturity::ParityPinned, CITE)
        .unwrap();
    atlas.set_maturity("y", Maturity::Stated, CITE).unwrap();
    atlas
        .add_equivalence(
            "x == y",
            "x",
            "y",
            Maturity::KernelChecked, // even a high equivalence rank cannot relax min-merge
            "fragment: recorded, union still performed",
            CITE,
        )
        .unwrap();
    atlas.saturate().unwrap();
    assert_eq!(atlas.maturity("x"), Some(Maturity::Stated));
    assert_eq!(atlas.maturity("y"), Some(Maturity::Stated));
    assert_eq!(
        atlas.fragments.get("x == y").map(String::as_str),
        Some("fragment: recorded, union still performed")
    );
}

#[test]
fn weakest_link_report_finds_the_three_discontinuities() {
    let fixtures = Fixtures::load(&Fixtures::default_dir()).unwrap();
    let text = report::weakest_link(&fixtures).unwrap();
    assert!(text.contains("END-TO-END MATURITY"));
    assert!(text.contains("[0 Unenforced]"));
    assert_eq!(text.matches("<- DISCONTINUITY").count(), 3);
    // every hop printed a provenance line
    assert!(text.matches("provenance:").count() >= 4);
}
