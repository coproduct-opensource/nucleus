//! Live parity, tested on the drift shapes it exists for: a context the
//! ledger lists that GitHub does not require (the three contexts PR #2642
//! introduced, before the admin step), a context GitHub requires that the
//! ledger never heard of, a queue constant edited in the UI (the 60-minute
//! timeout of 2026-09-04), and `strict` flipped.

use ci_spec::Severity;
use ci_spec::live::{LiveProtection, LiveQueue, parity};
use ci_spec::loader::from_parts;

const QUEUE: &str = r#"
ruleset_id = 22351600
check_response_timeout_minutes = 360
max_entries_to_build = 1
max_entries_to_merge = 1
min_entries_to_merge = 1
min_entries_to_merge_wait_minutes = 0
grouping_strategy = "ALLGREEN"
merge_method = "SQUASH"
strict = false
"#;

const WF: &str = r#"
name: CI
on:
  pull_request:
  merge_group:
jobs:
  a:
    name: Rustfmt
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - run: cargo fmt --check
  b:
    name: Clippy
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - run: cargo clippy
"#;

fn model_owned_by(ledger: &[&str], owner: &str) -> ci_spec::model::Model {
    let mut l = format!("# PINNED = {}\n", ledger.len());
    for c in ledger {
        l.push_str(c);
        l.push('\n');
    }
    from_parts(
        &[(".github/workflows/ci.yml".into(), WF.into())],
        &l,
        &format!("owner = \"{owner}\"\n{QUEUE}"),
        "# UNCOVERED_CEILING = 0\n",
        "",
        vec![],
    )
    .unwrap()
}

fn model(ledger: &[&str]) -> ci_spec::model::Model {
    let mut l = format!("# PINNED = {}\n", ledger.len());
    for c in ledger {
        l.push_str(c);
        l.push('\n');
    }
    from_parts(
        &[
            (".github/workflows/ci.yml".into(), WF.into()),
            (
                ".github/workflows/other.yml".into(),
                WF.replace("name: CI", "name: Other")
                    .replace("Rustfmt", "X")
                    .replace("Clippy", "Y"),
            ),
        ],
        &l,
        QUEUE,
        "# UNCOVERED_CEILING = 0\n",
        "",
        vec![],
    )
    .unwrap()
}

fn live(contexts: &[&str], strict: bool) -> LiveProtection {
    LiveProtection {
        strict,
        contexts: contexts.iter().map(|s| s.to_string()).collect(),
    }
}

fn queue() -> LiveQueue {
    LiveQueue {
        check_response_timeout_minutes: 360,
        max_entries_to_build: 1,
        max_entries_to_merge: 1,
        min_entries_to_merge: 1,
        min_entries_to_merge_wait_minutes: 0,
        grouping_strategy: "ALLGREEN".into(),
        merge_method: "SQUASH".into(),
    }
}

fn rules(f: &[ci_spec::Finding]) -> Vec<&'static str> {
    let mut v: Vec<&'static str> = f.iter().map(|x| x.rule).collect();
    v.sort_unstable();
    v.dedup();
    v
}

#[test]
fn lockstep_is_clean() {
    let f = parity(
        &model(&["Rustfmt", "Clippy"]),
        &live(&["Clippy", "Rustfmt"], false),
        Some(&queue()),
    );
    assert!(f.is_empty(), "{f:#?}");
}

#[test]
fn ledger_context_github_does_not_require_is_missing() {
    let f = parity(
        &model(&["Rustfmt", "Clippy", "Detect changed crates"]),
        &live(&["Clippy", "Rustfmt"], false),
        Some(&queue()),
    );
    assert_eq!(rules(&f), vec!["CI-LP-MISSING"]);
    assert_eq!(f[0].subject, "Detect changed crates");
    assert_eq!(f[0].severity, Severity::Critical);
}

#[test]
fn github_context_the_ledger_never_heard_of_is_extra() {
    let f = parity(
        &model(&["Rustfmt", "Clippy"]),
        &live(&["Clippy", "Rustfmt", "Mystery"], false),
        Some(&queue()),
    );
    assert_eq!(rules(&f), vec!["CI-LP-EXTRA"]);
}

#[test]
fn a_ui_edit_to_the_queue_timeout_is_drift() {
    let mut q = queue();
    q.check_response_timeout_minutes = 60;
    let f = parity(
        &model(&["Rustfmt", "Clippy"]),
        &live(&["Clippy", "Rustfmt"], false),
        Some(&q),
    );
    assert_eq!(rules(&f), vec!["CI-LP-QUEUE"]);
    assert!(f[0].why.contains("60"));
}

#[test]
fn strict_flipped_is_drift() {
    let f = parity(
        &model(&["Rustfmt", "Clippy"]),
        &live(&["Clippy", "Rustfmt"], true),
        Some(&queue()),
    );
    assert_eq!(rules(&f), vec!["CI-LP-STRICT"]);
}

#[test]
fn a_partial_protection_response_is_undecided_not_clean() {
    let f = parity(
        &model(&["Rustfmt", "Clippy"]),
        &live(&["Rustfmt"], false),
        Some(&queue()),
    );
    assert_eq!(rules(&f), vec!["CI-LP-VACUOUS"]);
    assert_eq!(f[0].severity, Severity::Undecided);
}

/// The cut: gatehouse's queue verifies receipts and calls the merge API. GitHub's queue must
/// then be gone — two queues merging one branch is exactly the state where the receipts that
/// were verified belong to a group GitHub never built.
#[test]
fn gatehouse_owning_the_merge_with_githubs_queue_still_on_is_a_conflict() {
    let f = parity(
        &model_owned_by(&["Rustfmt", "Clippy"], "gatehouse"),
        &live(&["Clippy", "Rustfmt"], true),
        Some(&queue()),
    );
    assert_eq!(rules(&f), vec!["CI-LP-QUEUE-OWNER"]);
}

#[test]
fn gatehouse_owning_the_merge_with_no_github_queue_is_clean() {
    let f = parity(
        &model_owned_by(&["Rustfmt", "Clippy"], "gatehouse"),
        &live(&["Clippy", "Rustfmt"], true),
        None,
    );
    assert!(f.is_empty(), "{f:?}");
}

/// And the other direction: the pin still says GitHub owns the merge, but nothing enforces a
/// queue. Nothing builds a group, and the capacity theorem is about a queue that does not run.
#[test]
fn github_owning_the_merge_with_no_queue_live_is_a_conflict() {
    let f = parity(
        &model_owned_by(&["Rustfmt", "Clippy"], "github"),
        &live(&["Clippy", "Rustfmt"], false),
        None,
    );
    assert_eq!(rules(&f), vec!["CI-LP-QUEUE-OWNER"]);
}

#[test]
fn a_ruleset_carries_a_merge_queue_only_while_it_is_enforced() {
    let with =
        r#"{"id":7,"enforcement":"active","rules":[{"type":"merge_queue","parameters":{}}]}"#;
    let off =
        r#"{"id":7,"enforcement":"disabled","rules":[{"type":"merge_queue","parameters":{}}]}"#;
    let without = r#"{"id":7,"enforcement":"active","rules":[{"type":"deletion"}]}"#;
    assert!(ci_spec::live::ruleset_has_merge_queue(with).unwrap());
    assert!(!ci_spec::live::ruleset_has_merge_queue(off).unwrap());
    assert!(!ci_spec::live::ruleset_has_merge_queue(without).unwrap());
    assert_eq!(
        ci_spec::live::parse_ruleset_ids(r#"[{"id":7,"name":"a"},{"id":9,"name":"b"}]"#).unwrap(),
        vec![7, 9]
    );
}
