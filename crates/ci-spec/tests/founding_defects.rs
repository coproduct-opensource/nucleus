//! Every invariant, tested on the defect it was written for.
//!
//! Each fixture is the shape found live on 2026-09-05 (or in the repo's
//! history), reduced to the minimum that reproduces it. The assertion is
//! two-sided, as in `scripts/check-gates-can-fail.sh`: the rule must fire on
//! the defect, and must be silent on the repaired shape — a rule that fires
//! on everything detects nothing either.

use ci_spec::loader::from_parts;
use ci_spec::{Severity, check};

const QUEUE: &str = r#"
ruleset_id = 1
check_response_timeout_minutes = 360
max_entries_to_build = 1
max_entries_to_merge = 1
min_entries_to_merge = 1
min_entries_to_merge_wait_minutes = 0
grouping_strategy = "ALLGREEN"
merge_method = "SQUASH"
strict = false
"#;

/// A second, always-clean workflow so the model is never vacuous (I9).
const FILLER: &str = r#"
name: Filler
on:
  push:
    branches: ["main"]
  pull_request:
  merge_group:
concurrency:
  group: filler-${{ github.head_ref || github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
jobs:
  rustfmt:
    name: Rustfmt
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - run: |
          cargo fmt --check || { echo "::error::fmt"; exit 1; }
  clippy:
    name: Clippy
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
      - run: |
          cargo clippy || { echo "::error::clippy"; exit 1; }
"#;

const FILLER_GATES: &str = "\
filler.yml::rustfmt::<unnamed> | falsified by cargo fmt on a misformatted fixture
filler.yml::clippy::<unnamed> | falsified by a clippy fixture
";

fn run(workflows: &[(&str, &str)], ledger: &str, inline_gates: &str) -> ci_spec::Report {
    let mut wfs: Vec<(String, String)> = workflows
        .iter()
        .map(|(p, t)| (format!(".github/workflows/{p}"), (*t).to_string()))
        .collect();
    wfs.push((".github/workflows/filler.yml".into(), FILLER.into()));
    let ledger = format!("{ledger}\nRustfmt\nClippy\n");
    let n = ledger
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .count();
    let ledger = format!("# PINNED = {n}\n{ledger}");
    let inline = format!("# UNCOVERED_CEILING = 50\n{FILLER_GATES}{inline_gates}");
    let m = from_parts(&wfs, &ledger, QUEUE, &inline, "", vec![]).expect("model");
    check(&m)
}

fn rules(r: &ci_spec::Report) -> Vec<&'static str> {
    r.findings
        .iter()
        .filter(|f| f.severity != Severity::Info)
        .map(|f| f.rule)
        .collect()
}

fn assert_clean(r: &ci_spec::Report) {
    let bad: Vec<_> = r
        .findings
        .iter()
        .filter(|f| f.severity != Severity::Info)
        .collect();
    assert!(bad.is_empty(), "expected clean, got {bad:#?}");
    assert_eq!(r.exit_code(), 0);
}

// ── I1 twin completeness ──────────────────────────────────────────────────

const REAL_KANI: &str = r#"
name: Kani BMC
on:
  pull_request:
    paths:
      - "crates/portcullis/src/**"
      - ".kani-minimum-proofs"
  merge_group:
concurrency:
  group: kani-real-${{ github.head_ref || github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
jobs:
  kani-fast:
    name: Kani
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    steps:
      - run: cargo kani
"#;

fn noop_kani(ignore: &[&str], group: &str, merge_group: bool) -> String {
    let mut s = String::from("name: Kani BMC\non:\n  pull_request:\n    paths-ignore:\n");
    for p in ignore {
        s.push_str(&format!("      - \"{p}\"\n"));
    }
    if merge_group {
        s.push_str("  merge_group:\n");
    }
    s.push_str(&format!(
        "concurrency:\n  group: {group}\n  cancel-in-progress: ${{{{ github.event_name == 'pull_request' }}}}\n\
         jobs:\n  kani-fast:\n    name: Kani\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n      - run: echo noop\n"
    ));
    s
}

#[test]
fn i1_twin_ignore_list_drift_is_red_and_the_mirror_is_green() {
    // The kani-nightly-noop scar: one path missing from paths-ignore.
    let drifted = noop_kani(
        &["crates/portcullis/src/**"],
        "kani-noop-${{ github.head_ref || github.ref }}",
        false,
    );
    let r = run(
        &[
            ("kani-nightly.yml", REAL_KANI),
            ("kani-nightly-noop.yml", &drifted),
        ],
        "Kani",
        "",
    );
    assert!(rules(&r).contains(&"CI-I1-PATHS"), "got {:?}", rules(&r));

    let exact = noop_kani(
        &["crates/portcullis/src/**", ".kani-minimum-proofs"],
        "kani-noop-${{ github.head_ref || github.ref }}",
        false,
    );
    let r = run(
        &[
            ("kani-nightly.yml", REAL_KANI),
            ("kani-nightly-noop.yml", &exact),
        ],
        "Kani",
        "",
    );
    assert_clean(&r);
}

#[test]
fn i1_twins_sharing_a_concurrency_group_is_red() {
    // #2399: the twins cancelled each other on every PR.
    let shared = noop_kani(
        &["crates/portcullis/src/**", ".kani-minimum-proofs"],
        "kani-real-${{ github.head_ref || github.ref }}",
        false,
    );
    let r = run(
        &[
            ("kani-nightly.yml", REAL_KANI),
            ("kani-nightly-noop.yml", &shared),
        ],
        "Kani",
        "",
    );
    assert!(rules(&r).contains(&"CI-I1-GROUP"), "got {:?}", rules(&r));
}

#[test]
fn i1_noop_twin_on_merge_group_is_red_when_the_context_is_required() {
    let mg = noop_kani(
        &["crates/portcullis/src/**", ".kani-minimum-proofs"],
        "kani-noop-${{ github.head_ref || github.ref }}",
        true,
    );
    let r = run(
        &[
            ("kani-nightly.yml", REAL_KANI),
            ("kani-nightly-noop.yml", &mg),
        ],
        "Kani",
        "",
    );
    assert!(rules(&r).contains(&"CI-I1-NOOP-MG"), "got {:?}", rules(&r));
}

// ── I2 producer injectivity ───────────────────────────────────────────────

#[test]
fn i2_one_context_from_two_twin_pairs_is_red() {
    // "Scoped Aeneas (Rust → Lean 4) + parity tests" from the IFC and the
    // OIDC→SPIFFE pairs — four jobs, two same-named check runs per PR.
    let pair = |stem: &str| {
        let real = format!(
            "name: {stem}\non:\n  pull_request:\n    paths:\n      - \"crates/{stem}/**\"\n  merge_group:\n\
             concurrency:\n  group: {stem}-real-${{{{ github.head_ref || github.ref }}}}\n  cancel-in-progress: ${{{{ github.event_name == 'pull_request' }}}}\n\
             jobs:\n  j:\n    name: Scoped Aeneas\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n      - run: lake build\n"
        );
        let noop = format!(
            "name: {stem}\non:\n  pull_request:\n    paths-ignore:\n      - \"crates/{stem}/**\"\n\
             concurrency:\n  group: {stem}-noop-${{{{ github.head_ref || github.ref }}}}\n  cancel-in-progress: ${{{{ github.event_name == 'pull_request' }}}}\n\
             jobs:\n  j:\n    name: Scoped Aeneas\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n      - run: echo noop\n"
        );
        (real, noop)
    };
    let (a, an) = pair("ifc");
    let (b, bn) = pair("oidc");
    let r = run(
        &[
            ("ifc.yml", &a),
            ("ifc-noop.yml", &an),
            ("oidc.yml", &b),
            ("oidc-noop.yml", &bn),
        ],
        "Scoped Aeneas",
        "",
    );
    assert!(rules(&r).contains(&"CI-I2-DUP"), "got {:?}", rules(&r));

    let r = run(
        &[("ifc.yml", &a), ("ifc-noop.yml", &an)],
        "Scoped Aeneas",
        "",
    );
    assert_clean(&r);
}

#[test]
fn i2_matrix_contexts_have_producers() {
    let deny = r#"
name: Deny
on:
  pull_request:
  merge_group:
jobs:
  deny:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    strategy:
      matrix:
        checks: [advisories, bans]
    steps:
      - run: cargo deny check ${{ matrix.checks }}
"#;
    let r = run(&[("deny.yml", deny)], "deny (advisories)\ndeny (bans)", "");
    assert_clean(&r);
    let r = run(&[("deny.yml", deny)], "deny (licenses)", "");
    assert!(rules(&r).contains(&"CI-I2-NONE"), "got {:?}", rules(&r));
}

// ── I3 reported under merge_group, not skippable ──────────────────────────

const CI_WITH_DETECTOR: &str = r#"
name: CI
on:
  pull_request:
  merge_group:
jobs:
  changed-crates:
    name: Detect changed crates
    runs-on: ubuntu-latest
    timeout-minutes: 5
    outputs:
      all: ${{ steps.d.outputs.all }}
    steps:
      - id: d
        run: echo all=true >> "$GITHUB_OUTPUT"
  test:
    name: Tests
    runs-on: ubuntu-latest
    timeout-minutes: 30
    needs: changed-crates
    if: ${{ needs.changed-crates.outputs.all == 'true' || needs.changed-crates.outputs.crates != '' }}
    steps:
      - run: cargo test
"#;

#[test]
fn i3_required_job_needing_a_non_required_detector_is_red() {
    let r = run(&[("ci.yml", CI_WITH_DETECTOR)], "Tests", "");
    assert!(rules(&r).contains(&"CI-I3-NEEDS"), "got {:?}", rules(&r));
    // Making the detector a required context is the repair.
    let r = run(
        &[("ci.yml", CI_WITH_DETECTOR)],
        "Tests\nDetect changed crates",
        "",
    );
    assert_clean(&r);
}

#[test]
fn i3_job_if_false_under_merge_group_is_red() {
    let wf = r#"
name: X
on:
  pull_request:
  merge_group:
jobs:
  t:
    name: Tests
    runs-on: ubuntu-latest
    timeout-minutes: 5
    if: ${{ github.event_name == 'pull_request' }}
    steps:
      - run: cargo test
"#;
    let r = run(&[("x.yml", wf)], "Tests", "");
    assert!(rules(&r).contains(&"CI-I3-SKIP"), "got {:?}", rules(&r));
}

#[test]
fn i3_missing_merge_group_trigger_is_red() {
    let wf = "name: X\non:\n  pull_request:\njobs:\n  t:\n    name: Tests\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n      - run: cargo test\n";
    let r = run(&[("x.yml", wf)], "Tests", "");
    assert!(rules(&r).contains(&"CI-I3-NOMG"), "got {:?}", rules(&r));
}

#[test]
fn i3_unmodelled_condition_is_undecided_not_green() {
    let wf = "name: X\non:\n  pull_request:\n  merge_group:\njobs:\n  t:\n    name: Tests\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    if: ${{ contains(github.ref, 'x') }}\n    steps:\n      - run: cargo test\n";
    let r = run(&[("x.yml", wf)], "Tests", "");
    assert!(r.findings.iter().any(|f| f.rule == "CI-I3-UNDECIDED"));
    assert_eq!(r.exit_code(), 2);
}

// ── I4 concurrency ────────────────────────────────────────────────────────

#[test]
fn i4_cancel_in_progress_true_under_merge_group_is_red() {
    let z = |cancel: &str| {
        format!(
            "name: Z\non:\n  push:\n    branches: [main]\n  pull_request:\n  merge_group:\n\
             concurrency:\n  group: z-${{{{ github.ref }}}}\n  cancel-in-progress: {cancel}\n\
             jobs:\n  z:\n    name: zizmor\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n      - run: uvx zizmor .\n"
        )
    };
    let r = run(&[("zizmor.yml", &z("true"))], "zizmor", "");
    assert!(rules(&r).contains(&"CI-I4-CANCEL"), "got {:?}", rules(&r));
    // feature-matrix.yml's shape: true for a queue ref.
    let r = run(
        &[("zizmor.yml", &z("${{ github.ref != 'refs/heads/main' }}"))],
        "zizmor",
        "",
    );
    assert!(rules(&r).contains(&"CI-I4-CANCEL"), "got {:?}", rules(&r));
    let r = run(
        &[(
            "zizmor.yml",
            &z("${{ github.event_name == 'pull_request' }}"),
        )],
        "zizmor",
        "",
    );
    assert_clean(&r);
}

// ── I5 scope parity ───────────────────────────────────────────────────────

#[test]
fn i5_widened_paths_not_in_pattern_is_red() {
    let wf = |paths: &str| {
        let head = format!("name: L\non:\n  pull_request:\n    paths:\n{paths}  merge_group:\n");
        let job = "jobs:\n  l:\n    name: lake build Ck\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n      - id: scope\n        env:\n          PATTERN: '^crates/ck-policy/'\n        run: echo relevant=true\n      - run: lake build\n";
        format!("{head}{job}")
    };
    let r = run(
        &[(
            "ck.yml",
            &wf("      - \"crates/ck-policy/**\"\n      - \"crates/ck-types/**\"\n"),
        )],
        "lake build Ck",
        "",
    );
    assert!(rules(&r).contains(&"CI-I5-PARITY"), "got {:?}", rules(&r));
    let r = run(
        &[("ck.yml", &wf("      - \"crates/ck-policy/**\"\n"))],
        "lake build Ck",
        "",
    );
    assert_clean(&r);
}

// ── I6 gate integrity ─────────────────────────────────────────────────────

fn gate_wf(step: &str) -> String {
    format!(
        "name: G\non:\n  pull_request:\n  merge_group:\njobs:\n  g:\n    name: Gate\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n{step}"
    )
}

/// The Proof Count Ratchet as it stood on main on 2026-09-05.
const RATCHET_BROKEN: &str = r#"      - name: Count Kani proofs
        run: |
          PORTCULLIS=$(grep -c '#\[kani::proof\]' crates/portcullis/src/kani.rs)
          CORE=$(grep -rc '#\[kani::proof\]' crates/portcullis-core/src/ || echo 0)
          PROOF_COUNT=$((PORTCULLIS + CORE))
          MINIMUM=$(cat .kani-minimum-proofs | tr -d '[:space:]')
          if [ "$PROOF_COUNT" -lt "$MINIMUM" ]; then
            echo "::error::Kani proof count regression"
            exit 1
          fi
"#;

const RATCHET_FIXED: &str = r#"      - name: Count Kani proofs
        run: |
          PROOF_COUNT=$(grep -rho '#\[kani::proof\]' crates/portcullis/src crates/portcullis-core/src | wc -l | tr -d ' ')
          MINIMUM=$(cat .kani-minimum-proofs | tr -d '[:space:]')
          [[ "$MINIMUM" =~ ^[0-9]+$ ]] || { echo "::error::pin is not an integer"; exit 1; }
          if [ "$PROOF_COUNT" -lt "$MINIMUM" ]; then
            echo "::error::Kani proof count regression"
            exit 1
          fi
"#;

#[test]
fn gi006_the_real_ratchet_is_caught_and_its_repair_is_clean() {
    let r = run(
        &[("cov.yml", &gate_wf(RATCHET_BROKEN))],
        "Gate",
        "cov.yml::g::Count Kani proofs | probe",
    );
    let f: Vec<_> = r.findings.iter().filter(|f| f.rule == "GI006").collect();
    assert!(!f.is_empty(), "got {:?}", r.rules());
    assert!(
        f.iter()
            .any(|f| f.severity == Severity::Critical && f.why.contains("PROOF_COUNT"))
    );
    let r = run(
        &[("cov.yml", &gate_wf(RATCHET_FIXED))],
        "Gate",
        "cov.yml::g::Count Kani proofs | probe",
    );
    assert_clean(&r);
}

/// The llvm-cov threshold steps as they stood on main.
const TEE_BROKEN: &str = r#"      - name: Workspace coverage (threshold gate)
        run: |
          cargo llvm-cov --all-features \
            --fail-under-lines 85 \
            --ignore-filename-regex '(tests/|kani\.rs)' 2>&1 | tee /tmp/cov.txt
          if [ ! -s /tmp/cov.txt ]; then echo "::error::no report"; exit 1; fi
"#;

#[test]
fn gi003_tee_under_the_default_shell_is_caught_and_shell_bash_is_clean() {
    let r = run(
        &[("cov.yml", &gate_wf(TEE_BROKEN))],
        "Gate",
        "cov.yml::g::Workspace coverage (threshold gate) | probe",
    );
    assert!(rules(&r).contains(&"GI003"), "got {:?}", rules(&r));
    let fixed = TEE_BROKEN.replace("        run: |", "        shell: bash\n        run: |");
    let r = run(
        &[("cov.yml", &gate_wf(&fixed))],
        "Gate",
        "cov.yml::g::Workspace coverage (threshold gate) | probe",
    );
    assert_clean(&r);
}

/// Verbatim from nucleus before the repair (proofcard's REAL_BROKEN): it
/// gated 93 theorems and could not fail.
const AXIOM_BROKEN: &str = r#"      - name: Assert enforcement core is sorryAx-free
        run: |
          AXIOMS="$(lake env lean PrintAxioms.lean 2>&1 || true)"
          echo "$AXIOMS"
          if echo "$AXIOMS" | grep -q 'sorryAx'; then
            echo "::error::an enforcement-core theorem depends on sorryAx."
            exit 1
          fi
          echo "OK: audited enforcement-core theorems are sorryAx-free."
"#;

const AXIOM_FIXED: &str = r#"      - name: Assert enforcement core is sorryAx-free
        run: |
          EXPECTED=$(grep -c '^#print axioms' PrintAxioms.lean)
          if ! AXIOMS="$(lake env lean PrintAxioms.lean 2>&1)"; then
            echo "::error::the axiom audit did not run to completion."
            exit 1
          fi
          REPORTED=$(printf '%s\n' "$AXIOMS" | grep -c "depends on axioms" || true)
          if [ "$REPORTED" -ne "$EXPECTED" ]; then
            echo "::error::audit incomplete: declared $EXPECTED theorems, got $REPORTED."
            exit 1
          fi
          if printf '%s\n' "$AXIOMS" | grep -q 'sorryAx'; then
            echo "::error::an enforcement-core theorem depends on sorryAx."
            exit 1
          fi
"#;

#[test]
fn gi001_the_real_axiom_gate_is_caught_and_its_repair_is_clean() {
    let key = "ax.yml::g::Assert enforcement core is sorryAx-free | probe";
    let r = run(&[("ax.yml", &gate_wf(AXIOM_BROKEN))], "Gate", key);
    assert!(rules(&r).contains(&"GI001"), "got {:?}", rules(&r));
    let r = run(&[("ax.yml", &gate_wf(AXIOM_FIXED))], "Gate", key);
    assert_clean(&r);
}

/// econ-lean.yml's sorry-ban before PR 0: a grep with no floor.
const GREP_NO_FLOOR: &str = r#"      - name: Ban sorry
        run: |
          if grep -rnE 'sorry' --include='*.lean' crates/econ/lean/Nucleus; then
            echo "ERROR: sorry"
            exit 1
          fi
"#;

const GREP_WITH_FLOOR: &str = r#"      - name: Ban sorry
        run: |
          FILES=$(find crates/econ/lean/Nucleus -name '*.lean' | wc -l | tr -d ' ')
          if [ "$FILES" -lt 1 ]; then
            echo "::error::scanned nothing"
            exit 1
          fi
          if grep -rnE 'sorry' --include='*.lean' crates/econ/lean/Nucleus; then
            echo "ERROR: sorry"
            exit 1
          fi
"#;

#[test]
fn gi002_grep_verdict_without_a_floor_is_caught_and_the_floor_is_clean() {
    let key = "e.yml::g::Ban sorry | probe";
    let r = run(&[("e.yml", &gate_wf(GREP_NO_FLOOR))], "Gate", key);
    assert!(rules(&r).contains(&"GI002"), "got {:?}", rules(&r));
    let r = run(&[("e.yml", &gate_wf(GREP_WITH_FLOOR))], "Gate", key);
    assert_clean(&r);
}

#[test]
fn gi004_continue_on_error_on_a_gate_step_is_critical() {
    let step =
        "      - name: gate\n        continue-on-error: true\n        run: |\n          exit 1\n";
    let r = run(
        &[("c.yml", &gate_wf(step))],
        "Gate",
        "c.yml::g::gate | probe",
    );
    assert!(
        r.findings
            .iter()
            .any(|f| f.rule == "GI004" && f.severity == Severity::Critical)
    );
}

#[test]
fn severity_is_scoped_to_required_contexts_but_critical_is_not() {
    // A tee under the default shell in a NON-required job: reported, not failed.
    let r = run(
        &[("cov.yml", &gate_wf(TEE_BROKEN))],
        "",
        "cov.yml::g::Workspace coverage (threshold gate) | probe",
    );
    assert!(
        r.findings
            .iter()
            .any(|f| f.rule == "GI003" && f.severity == Severity::Info)
    );
    assert_eq!(r.exit_code(), 0);
    // A gate that cannot fail is Critical wherever it sits.
    let r = run(
        &[("cov.yml", &gate_wf(RATCHET_BROKEN))],
        "",
        "cov.yml::g::Count Kani proofs | probe",
    );
    assert_eq!(r.exit_code(), 1);
}

// ── I7 timeouts ───────────────────────────────────────────────────────────

#[test]
fn i7_missing_and_oversized_timeouts_are_reported() {
    let wf = |t: &str| {
        format!(
            "name: T\non:\n  pull_request:\n  merge_group:\njobs:\n  a:\n    name: Audit\n    runs-on: ubuntu-latest\n{t}    steps:\n      - run: cargo audit\n"
        )
    };
    let r = run(&[("a.yml", &wf(""))], "Audit", "");
    assert!(
        rules(&r).contains(&"CI-I7-NOTIMEOUT"),
        "got {:?}",
        rules(&r)
    );
    let r = run(&[("a.yml", &wf("    timeout-minutes: 400\n"))], "Audit", "");
    assert!(rules(&r).contains(&"CI-I7-EXCEEDS"), "got {:?}", rules(&r));
    let r = run(&[("a.yml", &wf("    timeout-minutes: 15\n"))], "Audit", "");
    assert_clean(&r);
}

// ── I8 wired / inventoried ────────────────────────────────────────────────

#[test]
fn i8_unlisted_and_stale_inline_gates_are_reported() {
    let r = run(
        &[(
            "c.yml",
            &gate_wf(
                "      - name: g\n        run: |\n          test -f x || { echo \"::error::x\"; exit 1; }\n",
            ),
        )],
        "Gate",
        "",
    );
    assert!(rules(&r).contains(&"CI-I8-UNLISTED"), "got {:?}", rules(&r));
    let r = run(
        &[(
            "c.yml",
            &gate_wf(
                "      - name: g\n        run: |\n          test -f x || { echo \"::error::x\"; exit 1; }\n",
            ),
        )],
        "Gate",
        "c.yml::g::g | probe\nc.yml::g::gone | probe",
    );
    assert!(rules(&r).contains(&"CI-I8-STALE"), "got {:?}", rules(&r));
}

#[test]
fn i8_unwired_gate_script_is_reported() {
    let mut wfs = vec![(
        ".github/workflows/filler.yml".to_string(),
        FILLER.to_string(),
    )];
    wfs.push((".github/workflows/z.yml".into(), "name: Z\non:\n  pull_request:\n  merge_group:\njobs:\n  z:\n    name: Z\n    runs-on: ubuntu-latest\n    timeout-minutes: 5\n    steps:\n      - run: scripts/check-wired.sh\n".into()));
    let ledger = "# PINNED = 2\nRustfmt\nClippy\n";
    let inline = format!("# UNCOVERED_CEILING = 0\n{FILLER_GATES}");
    let m = from_parts(
        &wfs,
        ledger,
        QUEUE,
        &inline,
        "",
        vec![
            "scripts/check-wired.sh".into(),
            "scripts/check-orphan.sh".into(),
        ],
    )
    .unwrap();
    let r = check(&m);
    let unwired: Vec<_> = r
        .findings
        .iter()
        .filter(|f| f.rule == "CI-I8-UNWIRED")
        .collect();
    assert_eq!(unwired.len(), 1);
    assert_eq!(unwired[0].subject, "scripts/check-orphan.sh");
}

// ── I9 vacuity ────────────────────────────────────────────────────────────

#[test]
fn i9_an_empty_ledger_or_missing_pin_is_undecided_not_clean() {
    let m = from_parts(
        &[
            (".github/workflows/filler.yml".into(), FILLER.into()),
            (".github/workflows/k.yml".into(), REAL_KANI.into()),
        ],
        "",
        QUEUE,
        "# UNCOVERED_CEILING = 5\n",
        "",
        vec![],
    )
    .unwrap();
    let r = check(&m);
    assert!(r.findings.iter().any(|f| f.rule == "CI-I9-LEDGER"));
    assert_ne!(r.exit_code(), 0);
}

#[test]
fn allowlist_entries_go_stale_loudly() {
    let wfs = vec![
        (
            ".github/workflows/filler.yml".to_string(),
            FILLER.to_string(),
        ),
        (".github/workflows/k.yml".to_string(), REAL_KANI.to_string()),
        (
            ".github/workflows/k-noop.yml".to_string(),
            noop_kani(
                &["crates/portcullis/src/**", ".kani-minimum-proofs"],
                "kani-noop-x",
                false,
            ),
        ),
    ];
    let inline = format!("# UNCOVERED_CEILING = 0\n{FILLER_GATES}");
    let m = from_parts(
        &wfs,
        "# PINNED = 3\nRustfmt\nClippy\nKani\n",
        QUEUE,
        &inline,
        "GI003 .github/workflows/k.yml::kani-fast/x | no longer exists\n",
        vec![],
    )
    .unwrap();
    let r = check(&m);
    assert!(
        r.findings.iter().any(|f| f.rule == "CI-ALLOW-STALE"),
        "got {:?}",
        r.rules()
    );
}
