//! `cargo xtask assurance-required` — a claim's falsifier must produce a REQUIRED context.
//!
//! `scripts/check-ci-assurance-ledger.sh` already refuses a claim whose falsifier does not exist,
//! and refuses one that no workflow invokes: *"a gate CI does not run enforces nothing."* That
//! sentence has a second half it does not check. A gate CI runs, that goes red, and that the merge
//! queue merges past anyway **also** enforces nothing — it is a red light beside an open gate.
//!
//! The merge queue gates on the contexts in `ci/required-checks.txt` and on nothing else. So a
//! falsifier whose job is not among them is advisory: it can fail on every PR and every push to
//! main, and the queue will keep merging.
//!
//! # Measured, 2026-09-11
//!
//! **Six** of the eight non-`NOT-YET` rows of `docs/assurance/ci-assurance.md` have falsifiers that
//! produce no required context — **including two of the four `PROVED` rows**, whose falsifier is the
//! thing that would catch a proved claim regressing:
//!
//! | rows | falsifier | its context | required |
//! |---|---|---|---|
//! | CI-1, CI-2 (PROVED), CI-3 | `scripts/check-ci-spec.sh` | `CI configuration is sound (CI-1)` | no |
//! | CI-4 | `scripts/check-gates-can-fail.sh` | `Live-path gates (one pod)` | no |
//! | CI-5, CI-8 | `.github/workflows/ci-assurance.yml` | its two jobs' contexts | no |
//! | CI-6, CI-7 (PROVED) | `check-ci-spec-golden.sh`, `-bite.sh` | `lake build CiSpec (…)` | yes |
//!
//! I counted FOUR by reading the table before writing this gate, and it found six. CI-5 and CI-8
//! name a WORKFLOW as their falsifier rather than a script, so their contexts are that workflow's
//! jobs, and I did not look. That is the argument for the gate over the report, made against me.
//!
//! This is the general form of `FINDINGS.md` F-41, which found the same hole under one specific
//! check: `a real nucleus pod boots and is enforced (x86_64)` is not required, so `main` was red on
//! it for 2h24m while the queue merged nine PRs through.
//!
//! # What this gate does NOT do
//!
//! **It does not decide that these six should be required.** That is a judgement about cost and
//! flakiness — the pod-boot check boots a real Firecracker microVM on a self-hosted runner, and
//! requiring it makes one machine's availability a merge dependency (F-40). So the count is
//! RATCHETED, not driven to zero: it is pinned at what is true today, may only shrink, and a
//! seventh unrequired falsifier is a red. Making the gap visible and un-growable is a smaller claim than
//! closing it, and it is the one this gate can honestly make.
//!
//! # Where the mapping comes from
//!
//! Not from a YAML parser written here. `ci_spec::loader::from_repo` loads the workflows and
//! `Job::contexts()` is the authoritative job → check-run mapping, matrix expansion included —
//! reused rather than re-derived, because five copies of one parser is `FINDINGS.md` F-36 and this
//! would have been the sixth.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

const LEDGER: &str = "docs/assurance/ci-assurance.md";
const RATCHET: &str = "ci/assurance-required-ratchet.txt";

/// One ledger row, reduced to what this gate reads.
struct Row {
    id: String,
    status: String,
    falsifier: Option<String>,
}

/// The `| CI-n | clause | status | evidence | falsified by |` rows.
///
/// The falsifier is the FIFTH column and the first backticked handle in it. Taking the column by
/// position rather than by searching the line matters: the evidence column is also full of
/// backticked handles, and reading one of those as the falsifier silently checks the wrong thing.
fn rows(text: &str) -> Vec<Row> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim_start();
        if !t.starts_with("| CI-") {
            continue;
        }
        let cols: Vec<&str> = line.split('|').map(str::trim).collect();
        // ["", id, clause, status, evidence, falsified-by, ""]
        if cols.len() < 6 {
            continue;
        }
        let first_handle = |s: &str| {
            s.split('`')
                .nth(1)
                .map(str::to_string)
                .filter(|h| !h.is_empty())
        };
        out.push(Row {
            id: cols[1].to_string(),
            status: cols[3].to_string(),
            falsifier: first_handle(cols[5]),
        });
    }
    out
}

/// The pinned number of non-`NOT-YET` rows whose falsifier produces no required context.
fn pinned(root: &Path) -> Result<usize> {
    let text = fs::read_to_string(root.join(RATCHET))
        .with_context(|| format!("{RATCHET} is missing — nothing to ratchet against"))?;
    text.lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("UNREQUIRED_FALSIFIERS="))
        .and_then(|v| v.trim().parse().ok())
        .with_context(|| format!("{RATCHET} has no UNREQUIRED_FALSIFIERS= line"))
}

/// The verdict, separated from the reading of it.
///
/// Pure over its three inputs so the interesting half is testable without a repository on disk.
/// That is not only for coverage: the shape of the failure this whole gate exists to prevent is a
/// check that looks right and decides nothing, and a decision procedure nobody can call is exactly
/// the thing that acquires that property quietly.
///
/// Returns `(descriptions of rows whose falsifier produces no required context, rows examined)`.
fn decide(
    rows: &[Row],
    workflows: &[ci_spec::model::Workflow],
    required: &BTreeSet<&str>,
) -> Result<(Vec<String>, usize)> {
    let mut unrequired = Vec::new();
    let mut checked = 0usize;
    for row in rows {
        if row.status == "NOT-YET" {
            continue;
        }
        let Some(f) = &row.falsifier else {
            // The ledger gate owns this failure; not restating it here would be two gates
            // disagreeing about the same row.
            bail!("{} is {} and names no falsifier", row.id, row.status);
        };
        checked += 1;

        // Every context produced by a job that invokes this falsifier. A workflow named as the
        // falsifier (some rows name `.github/workflows/x.yml`) counts every job in it.
        let mut produced: BTreeSet<String> = BTreeSet::new();
        for w in workflows {
            let names_workflow = w.path.ends_with(f.trim_start_matches("./"));
            for j in &w.jobs {
                let runs_it = names_workflow
                    || j.steps
                        .iter()
                        .any(|s| s.run.as_deref().is_some_and(|r| r.contains(f.as_str())));
                if runs_it {
                    produced.extend(j.contexts());
                }
            }
        }

        if produced.is_empty() {
            bail!(
                "{}'s falsifier {f:?} is run by no job — the ledger gate should have caught this first",
                row.id
            );
        }
        if !produced.iter().any(|c| required.contains(c.as_str())) {
            unrequired.push(format!(
                "{} ({}) — {f} produces {:?}, none required",
                row.id,
                row.status,
                produced.iter().take(3).collect::<Vec<_>>()
            ));
        }
    }
    Ok((unrequired, checked))
}

pub fn check(root: &Path) -> Result<()> {
    let model = ci_spec::loader::from_repo(root)?;
    let required: BTreeSet<&str> = model.ledger.contexts.iter().map(String::as_str).collect();
    if required.len() < 10 {
        bail!(
            "only {} required context(s) loaded — the required set did not load, so every \
             falsifier below would read as unrequired and this gate would be noise",
            required.len()
        );
    }

    let text =
        fs::read_to_string(root.join(LEDGER)).with_context(|| format!("{LEDGER} not found"))?;
    let rows = rows(&text);
    if rows.len() < 2 {
        bail!(
            "{LEDGER} yielded {} row(s) — the parse is wrong, so this gate examined nothing",
            rows.len()
        );
    }

    let (unrequired, checked) = decide(&rows, &model.workflows, &required)?;

    if checked == 0 {
        bail!("no non-NOT-YET row was examined — every claim would pass vacuously");
    }

    let pin = pinned(root)?;
    for u in &unrequired {
        println!("  unrequired  {u}");
    }
    if unrequired.len() > pin {
        bail!(
            "{} claim(s) have a falsifier that produces no required context, pin {pin} — \
             a falsifier the merge queue does not gate on is a red light beside an open gate. \
             Require the context, or raise the pin with the reason it stays advisory",
            unrequired.len()
        );
    }
    if unrequired.len() < pin {
        bail!(
            "{} unrequired falsifier(s), pin {pin} — lower the pin in the same change that \
             required one",
            unrequired.len()
        );
    }
    println!(
        "OK: {checked} non-NOT-YET claim(s) checked against {} required context(s); \
         {} falsifier(s) still advisory (pin {pin})",
        required.len(),
        unrequired.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Row, decide, rows};
    use std::collections::BTreeSet;

    /// The falsifier is the FIFTH column. The EVIDENCE column is also full of backticked handles,
    /// and reading one of those instead is a mistake that leaves the gate checking the wrong thing
    /// while still reporting a number — which is what it looks like when a gate is decorative.
    /// I made exactly this mistake while writing the parser, and the first run of the gate checked
    /// evidence handles against the required set.
    #[test]
    fn the_falsifier_comes_from_the_fifth_column_not_the_evidence() {
        let doc = "\
| # | Clause | Status | Evidence | Falsified by |
|---|---|---|---|---|
| CI-1 | \"a clause\" | PROVED | `crates/evidence/src/lib.rs#sym`, `docs/other.md` | `scripts/check-the-falsifier.sh` |
";
        let r = rows(doc);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].id, "CI-1");
        assert_eq!(r[0].status, "PROVED");
        assert_eq!(
            r[0].falsifier.as_deref(),
            Some("scripts/check-the-falsifier.sh"),
            "took a handle from the evidence column"
        );
    }

    /// Header and separator rows are not claims. A parser that counted them would inflate the
    /// population and dilute the ratchet.
    #[test]
    fn only_ci_numbered_rows_are_claims() {
        let doc =
            "| # | Clause |\n|---|---|\n| CI-7 | x | DECIDED | `e` | `f` |\n| note | not a row |\n";
        assert_eq!(rows(doc).len(), 1);
    }

    fn row(id: &str, status: &str, f: Option<&str>) -> Row {
        Row {
            id: id.into(),
            status: status.into(),
            falsifier: f.map(Into::into),
        }
    }

    fn workflow(yaml: &str) -> ci_spec::model::Workflow {
        ci_spec::loader::parse_workflow(".github/workflows/t.yml", yaml).expect("parses")
    }

    const WF: &str = "\
name: T
on: [push]
jobs:
  gated:
    name: The required one
    runs-on: ubuntu-latest
    steps:
      - run: scripts/check-required.sh
  ungated:
    name: The advisory one
    runs-on: ubuntu-latest
    steps:
      - run: scripts/check-advisory.sh
";

    #[test]
    fn a_falsifier_whose_context_is_required_is_not_reported() {
        let wfs = vec![workflow(WF)];
        let required: BTreeSet<&str> = ["The required one"].into_iter().collect();
        let (un, checked) = decide(
            &[row("CI-1", "PROVED", Some("scripts/check-required.sh"))],
            &wfs,
            &required,
        )
        .unwrap();
        assert_eq!(checked, 1);
        assert!(un.is_empty(), "{un:?}");
    }

    /// The whole point: the gate CI runs, and the queue does not gate on it.
    #[test]
    fn a_falsifier_whose_context_is_not_required_is_reported() {
        let wfs = vec![workflow(WF)];
        let required: BTreeSet<&str> = ["The required one"].into_iter().collect();
        let (un, checked) = decide(
            &[row("CI-2", "DECIDED", Some("scripts/check-advisory.sh"))],
            &wfs,
            &required,
        )
        .unwrap();
        assert_eq!(checked, 1);
        assert_eq!(un.len(), 1);
        assert!(un[0].contains("CI-2"), "{un:?}");
    }

    /// A `NOT-YET` row is a claim nobody is making yet; it owes no falsifier and must not be
    /// counted, or the ratchet would move when a row is promoted for unrelated reasons.
    #[test]
    fn not_yet_rows_are_skipped_and_uncounted() {
        let wfs = vec![workflow(WF)];
        let required: BTreeSet<&str> = ["The required one"].into_iter().collect();
        let (un, checked) = decide(&[row("CI-9", "NOT-YET", None)], &wfs, &required).unwrap();
        assert_eq!(checked, 0);
        assert!(un.is_empty());
    }

    /// A live row with no falsifier is the ledger gate's failure, and this one refuses rather than
    /// passing it over — two gates silently disagreeing about a row is worse than either failing.
    #[test]
    fn a_live_row_without_a_falsifier_is_an_error() {
        let wfs = vec![workflow(WF)];
        let required: BTreeSet<&str> = ["The required one"].into_iter().collect();
        assert!(decide(&[row("CI-3", "PROVED", None)], &wfs, &required).is_err());
    }

    /// A falsifier no job runs is the ledger gate's failure too, and reporting it as "advisory"
    /// would quietly fold a missing gate into the ratchet instead of failing.
    #[test]
    fn a_falsifier_no_job_runs_is_an_error() {
        let wfs = vec![workflow(WF)];
        let required: BTreeSet<&str> = ["The required one"].into_iter().collect();
        assert!(
            decide(
                &[row("CI-4", "PROVED", Some("scripts/check-nowhere.sh"))],
                &wfs,
                &required
            )
            .is_err()
        );
    }
}
