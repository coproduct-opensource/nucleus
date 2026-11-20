//! Explicit consent changed no built-in policy's decisions.
//!
//! Before consent was explicit, an operation above `Never` with no obligation
//! ran autonomously by omission. Every built-in profile — the hardcoded
//! constructors and the YAML ones — now declares that autonomy by name. This
//! test pins, op by op, that the decisions are exactly what they were.
//!
//! `MAIN` was produced on origin/main `2c13a37a2` (before the change) by
//! printing, for each profile, every operation above `Never` with its level and
//! whether `requires_approval` held (`R`) or not (`A`). It is the measured
//! "before"; the test renders the same line from the current code — the
//! "after" — and requires equality. `hard/default` is
//! `PermissionLattice::default()` there and `PermissionLattice::supervised()`
//! here: the same policy, renamed because a policy no longer has a default
//! (ADR 0007 B-1).

use portcullis::profile::ProfileRegistry;
use portcullis::{CapabilityLevel, Operation, PermissionLattice};

const MAIN: &[&str] = &[
    "hard/default ReadFiles:Always:A WriteFiles:LowRisk:R EditFiles:LowRisk:R GlobSearch:Always:A GrepSearch:Always:A WebSearch:LowRisk:R WebFetch:LowRisk:R GitCommit:LowRisk:R CreatePr:LowRisk:R",
    "hard/permissive ReadFiles:Always:A WriteFiles:Always:A EditFiles:Always:A RunBash:Always:R GlobSearch:Always:A GrepSearch:Always:A WebSearch:Always:A WebFetch:Always:A GitCommit:Always:A GitPush:Always:R CreatePr:Always:R ManagePods:Always:A SpawnAgent:Always:A",
    "hard/restrictive ReadFiles:Always:A GlobSearch:Always:A GrepSearch:Always:A",
    "hard/read_only ReadFiles:Always:A GlobSearch:Always:A GrepSearch:Always:A",
    "hard/filesystem_readonly ReadFiles:Always:A GlobSearch:Always:A GrepSearch:Always:A",
    "hard/network_only WebSearch:LowRisk:A WebFetch:LowRisk:A",
    "hard/web_research ReadFiles:LowRisk:A GlobSearch:Always:A GrepSearch:Always:A WebSearch:LowRisk:A WebFetch:LowRisk:A",
    "hard/code_review ReadFiles:Always:A GlobSearch:Always:A GrepSearch:Always:A WebSearch:LowRisk:R",
    "hard/edit_only ReadFiles:Always:A WriteFiles:LowRisk:A EditFiles:LowRisk:A GlobSearch:Always:A GrepSearch:Always:A",
    "hard/local_dev ReadFiles:Always:A WriteFiles:LowRisk:A EditFiles:LowRisk:A RunBash:LowRisk:A GlobSearch:Always:A GrepSearch:Always:A GitCommit:LowRisk:A",
    "hard/fix_issue ReadFiles:Always:A WriteFiles:LowRisk:A EditFiles:LowRisk:A RunBash:LowRisk:R GlobSearch:Always:A GrepSearch:Always:A WebSearch:LowRisk:R WebFetch:LowRisk:R GitCommit:LowRisk:R GitPush:LowRisk:R CreatePr:LowRisk:R SpawnAgent:LowRisk:A",
    "hard/safe_pr_fixer ReadFiles:Always:A WriteFiles:LowRisk:A EditFiles:LowRisk:A RunBash:LowRisk:R GlobSearch:Always:A GrepSearch:Always:A WebFetch:LowRisk:A GitCommit:LowRisk:A",
    "hard/release ReadFiles:Always:A WriteFiles:LowRisk:A EditFiles:LowRisk:A RunBash:LowRisk:R GlobSearch:Always:A GrepSearch:Always:A WebSearch:LowRisk:A WebFetch:LowRisk:A GitCommit:LowRisk:A GitPush:LowRisk:R CreatePr:LowRisk:R",
    "hard/database_client RunBash:LowRisk:A",
    "hard/demo ReadFiles:Always:A WriteFiles:LowRisk:R EditFiles:LowRisk:R RunBash:LowRisk:R GlobSearch:Always:A GrepSearch:Always:A WebSearch:LowRisk:A WebFetch:LowRisk:A GitCommit:LowRisk:A GitPush:LowRisk:R CreatePr:LowRisk:R",
    "hard/pr_review ReadFiles:Always:A GlobSearch:Always:A GrepSearch:Always:A WebSearch:LowRisk:A WebFetch:LowRisk:A",
    "hard/codegen ReadFiles:Always:A WriteFiles:LowRisk:A EditFiles:LowRisk:A RunBash:LowRisk:A GlobSearch:Always:A GrepSearch:Always:A GitCommit:LowRisk:A",
    "hard/pr_approve ReadFiles:Always:A RunBash:LowRisk:R GlobSearch:Always:A GrepSearch:Always:A WebSearch:LowRisk:A WebFetch:LowRisk:A GitPush:LowRisk:R",
    "hard/orchestrator ReadFiles:LowRisk:A GlobSearch:LowRisk:A GrepSearch:LowRisk:A ManagePods:Always:A SpawnAgent:Always:A",
    "yaml/code-review ReadFiles:Always:A GlobSearch:Always:A GrepSearch:Always:A WebSearch:LowRisk:R",
    "yaml/codegen ReadFiles:Always:A WriteFiles:LowRisk:A EditFiles:LowRisk:A RunBash:LowRisk:A GlobSearch:Always:A GrepSearch:Always:A GitCommit:LowRisk:A",
    "yaml/doc-editor ReadFiles:Always:A WriteFiles:LowRisk:A EditFiles:LowRisk:A GlobSearch:Always:A GrepSearch:Always:A GitCommit:LowRisk:A",
    "yaml/local-dev ReadFiles:Always:A WriteFiles:LowRisk:A EditFiles:LowRisk:A RunBash:LowRisk:A GlobSearch:Always:A GrepSearch:Always:A GitCommit:LowRisk:A",
    "yaml/read-only ReadFiles:Always:A GlobSearch:Always:A GrepSearch:Always:A",
    "yaml/release ReadFiles:Always:A WriteFiles:LowRisk:A EditFiles:LowRisk:A RunBash:LowRisk:R GlobSearch:Always:A GrepSearch:Always:A WebSearch:LowRisk:A WebFetch:LowRisk:A GitCommit:LowRisk:A GitPush:LowRisk:R CreatePr:LowRisk:R",
    "yaml/research-web ReadFiles:LowRisk:A GlobSearch:Always:A GrepSearch:Always:A WebSearch:LowRisk:A WebFetch:LowRisk:A",
    "yaml/safe-pr-fixer ReadFiles:Always:A WriteFiles:LowRisk:A EditFiles:LowRisk:A RunBash:LowRisk:R GlobSearch:Always:A GrepSearch:Always:A WebFetch:LowRisk:A GitCommit:LowRisk:A",
    "yaml/test-runner ReadFiles:Always:A RunBash:LowRisk:A GlobSearch:Always:A GrepSearch:Always:A",
    "yaml/triage-bot ReadFiles:Always:A GlobSearch:Always:A GrepSearch:Always:A WebSearch:LowRisk:A WebFetch:LowRisk:A",
    "yaml/untrusted-model ReadFiles:LowRisk:A WriteFiles:LowRisk:A EditFiles:LowRisk:A GlobSearch:Always:A GrepSearch:Always:A",
];

fn render(name: &str, l: &PermissionLattice) -> String {
    let mut out = Vec::new();
    for op in Operation::ALL {
        let lvl = l.capabilities.level_for(op);
        if lvl == CapabilityLevel::Never {
            continue;
        }
        let c = if l.requires_approval(op) { "R" } else { "A" };
        out.push(format!("{op:?}:{lvl:?}:{c}"));
    }
    format!("{name} {}", out.join(" "))
}

fn current() -> Vec<(String, PermissionLattice)> {
    let mut all: Vec<(String, PermissionLattice)> = vec![
        ("hard/default".into(), PermissionLattice::supervised()),
        ("hard/permissive".into(), PermissionLattice::permissive()),
        ("hard/restrictive".into(), PermissionLattice::restrictive()),
        ("hard/read_only".into(), PermissionLattice::read_only()),
        (
            "hard/filesystem_readonly".into(),
            PermissionLattice::filesystem_readonly(),
        ),
        (
            "hard/network_only".into(),
            PermissionLattice::network_only(),
        ),
        (
            "hard/web_research".into(),
            PermissionLattice::web_research(),
        ),
        ("hard/code_review".into(), PermissionLattice::code_review()),
        ("hard/edit_only".into(), PermissionLattice::edit_only()),
        ("hard/local_dev".into(), PermissionLattice::local_dev()),
        ("hard/fix_issue".into(), PermissionLattice::fix_issue()),
        (
            "hard/safe_pr_fixer".into(),
            PermissionLattice::safe_pr_fixer(),
        ),
        ("hard/release".into(), PermissionLattice::release()),
        (
            "hard/database_client".into(),
            PermissionLattice::database_client(),
        ),
        ("hard/demo".into(), PermissionLattice::demo()),
        ("hard/pr_review".into(), PermissionLattice::pr_review()),
        ("hard/codegen".into(), PermissionLattice::codegen()),
        ("hard/pr_approve".into(), PermissionLattice::pr_approve()),
        (
            "hard/orchestrator".into(),
            PermissionLattice::orchestrator(),
        ),
    ];
    let reg = ProfileRegistry::canonical().expect("built-in profiles parse");
    let mut names: Vec<String> = reg.names().iter().map(|s| s.to_string()).collect();
    names.sort();
    for n in names {
        let l = reg.resolve(&n).expect("built-in profile builds");
        all.push((format!("yaml/{n}"), l));
    }
    all
}

#[test]
fn every_builtin_profile_decides_consent_exactly_as_before() {
    let now: Vec<String> = current().iter().map(|(n, l)| render(n, l)).collect();
    // Coverage first: a profile added or dropped on either side is a failure,
    // not a silently shorter comparison.
    let names = |v: &[String]| -> Vec<String> {
        v.iter()
            .map(|l| l.split(' ').next().unwrap_or("").to_string())
            .collect()
    };
    let before: Vec<String> = MAIN.iter().map(|s| s.to_string()).collect();
    assert_eq!(
        names(&now),
        names(&before),
        "the set of built-in profiles changed"
    );
    for (b, n) in before.iter().zip(&now) {
        assert_eq!(n, b, "a built-in profile's consent changed");
    }
}

#[test]
fn every_builtin_profile_declares_every_permitted_operation() {
    for (name, l) in current() {
        assert_eq!(
            l.check_consent(),
            Ok(()),
            "{name}: consent must be declared for every operation above never"
        );
        // And the raw set IS the decided one: no built-in obligates an
        // operation it forbids, so its checksum is the one it had before.
        assert_eq!(
            l.obligations,
            l.effective_obligations(),
            "{name}: raw obligations must equal the decided obligations"
        );
    }
}

/// The bytes a pinned 2.7.0 guest hashes did not move.
///
/// A node newer than its guest sends the admitted lattice in the pod
/// certificate. The 2.7.0 guest ignores the `autonomous` key (its
/// `RawPermissionLattice` has no `deny_unknown_fields`), then (1) verifies the
/// certificate's Ed25519 signatures over `canonical_permissions_hash`, and (2)
/// computes `program_digest` over `program_checksum`, which the node compares
/// with its own and refuses a workload result on mismatch. Both must be
/// byte-identical to what the node computes. These values were produced on
/// origin/main `2c13a37a2`, whose digest code is unchanged since `v2.7.0`.
/// `permissive ∧ codegen` is the shape the node admits: it keeps the ceiling's
/// obligations on operations the profile forbids, which is why
/// `program_checksum` hashes the RAW set.
#[cfg(feature = "crypto")]
#[test]
fn the_digests_a_pinned_guest_recomputes_are_unchanged() {
    use chrono::{TimeZone, Utc};
    use portcullis::certificate::canonical_permissions_hash;
    use portcullis::TimeLattice;

    fn fixed(mut l: PermissionLattice) -> PermissionLattice {
        l.time = TimeLattice::between(
            Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 1, 2, 0, 0, 0).unwrap(),
        );
        l
    }
    let cases = [
        (
            "codegen",
            fixed(PermissionLattice::codegen()),
            "75f8737649eea3b54f5e21218de652547f9276f61c659789194243464603ac99",
            "220f90ee09333b1f0959b6a5ddbc39a5d37c4e2673b5bdfc7cead3d73ff54292",
        ),
        (
            "release",
            fixed(PermissionLattice::release()),
            "83528e13eb1cc1e92e2bc9c71a0cd70ff118a64381790b532b5cb1f8596dd2bb",
            "6321ee0db126587ce074fdb5cd805a5b1c73825236fa4717848c841b909a329c",
        ),
        (
            "permissive_meet_codegen",
            fixed(PermissionLattice::permissive().meet(&PermissionLattice::codegen())),
            "730ce68f85fa219ee52bca4925f18bb7a961a978579a308d37f9fc4e6b235299",
            "7f07eac4695f724fc6812cbbeea4fead5e047555f035fd3a3efb3889616c961a",
        ),
    ];
    for (name, l, program, canonical) in cases {
        let h: String = canonical_permissions_hash(&l)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(l.program_checksum(), program, "{name}: program_checksum");
        assert_eq!(h, canonical, "{name}: canonical_permissions_hash");
    }
}
