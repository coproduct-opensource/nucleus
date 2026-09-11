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

    let mut unrequired = Vec::new();
    let mut checked = 0usize;
    for row in &rows {
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
        for w in &model.workflows {
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
