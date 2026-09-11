//! `cargo xtask ci-facts` — CI timings from the Actions API into a store that outlives them.
//!
//! **Why this exists at all, stated as the correction it came from.** This was scoped believing
//! nucleus had no CI measurement machinery. It has two working pullers (`ci_timings`, `ci_otel`),
//! a metric vocabulary, a cron and committed dashboards — and the half that was deleted at the
//! 2026-09-09 Fly cutover is the half that was about to be rebuilt. `ci-metrics.yml` has run
//! every fifteen minutes since, pulling perfectly and exporting to an address that no longer
//! resolves, and its own header names the next step: *"gatehouse-controld has no OTLP ingest
//! today… Pointing this at gatehouse means adding an ingest route there first."* This is the
//! caller of that route.
//!
//! The direction is inverted from `ci_otel`'s on purpose. That pushed AGGREGATES (histograms,
//! already bucketed) to a collector; a bucket cannot be re-cut, and every one of F-80, F-81 and
//! F-82 was a finer cut of data already gathered. So this posts ROWS and lets the questions be
//! asked later.
//!
//! **What is written and what is not.** A row is a fact only once its subject is terminal, so a
//! job still in flight is skipped and re-read next window. GitHub reports cancelled and skipped
//! jobs as `completed` too, and those ARE written — with a null start where no runner took them.
//! A job that waited and was then cancelled is precisely the evidence the wait question needs,
//! and dropping it would bias every wait distribution toward the jobs that got a machine.
//!
//! Usage: `cargo xtask ci-facts ingest --since MIN [--url URL] [--tenant T] [--dry-run]`
//! (`--url` defaults to `$GATEHOUSE_URL`, the token to `$GATEHOUSE_TOKEN`; needs `gh`
//! authenticated, or `GH_API_FIXTURES` — see `crate::gh_actions`.)

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::gh_actions::{JobList, REPO, RunList, epoch, gh_api, rfc3339};

/// Seconds to microseconds, the unit gatehouse's store keeps every clock in.
fn micros(secs: i64) -> u64 {
    u64::try_from(secs).unwrap_or(0).saturating_mul(1_000_000)
}

fn now_secs() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
    .unwrap_or(i64::MAX)
}

/// What one window's pull produced, before it is posted.
#[derive(Debug, Default)]
pub struct Facts {
    pub runs: Vec<Value>,
    pub jobs: Vec<Value>,
    pub steps: Vec<Value>,
}

impl Facts {
    fn is_empty(&self) -> bool {
        self.runs.is_empty() && self.jobs.is_empty() && self.steps.is_empty()
    }
}

/// Pull every run and job that reached a terminal state in `[window_start, now)`.
///
/// The runs query reaches an hour further back than the window, because a long run's jobs finish
/// long after it was created and a run created outside the window can still hold jobs inside it.
/// That is `ci_otel`'s rule and it is copied deliberately rather than re-derived: two windows
/// that disagree about which jobs they contain are two answers to the same question.
///
/// `fetch` is the API, passed in rather than called here so the WINDOWING — which is all the
/// judgement in this function — is testable at a fixed clock. The same split
/// `gate::observe::derive` makes for `exists` in gatehouse, and for the same reason: the
/// subprocess is not the part that can be subtly wrong.
pub fn pull(window_start: i64, now: i64, fetch: &dyn Fn(&str) -> Result<String>) -> Result<Facts> {
    let since = rfc3339(window_start - 3600);
    let runs: RunList = serde_json::from_str(&fetch(&format!(
        "repos/{REPO}/actions/runs?created=>={since}&per_page=100"
    ))?)
    .context("parse run list")?;

    let mut f = Facts::default();
    for run in &runs.workflow_runs {
        let wf = run.name.clone().unwrap_or_default();
        let list: JobList = serde_json::from_str(&fetch(&format!(
            "repos/{REPO}/actions/runs/{}/jobs?per_page=100",
            run.id
        ))?)
        .with_context(|| format!("parse jobs of run {}", run.id))?;

        let mut run_is_in_window = false;
        for j in &list.jobs {
            // Terminal, and finished inside the window. `status == "completed"` is GitHub's
            // terminal marker and covers cancelled and skipped; `conclusion` says which.
            if j.status != "completed" {
                continue;
            }
            let Some(done) = j.completed_at.as_deref().and_then(epoch) else {
                continue;
            };
            if done < window_start || done >= now {
                continue;
            }
            let Some(created) = epoch(&j.created_at) else {
                continue;
            };
            run_is_in_window = true;
            let started = j.started_at.as_deref().and_then(epoch);
            f.jobs.push(json!({
                "job_id": j.id, "run_id": run.id,
                "workflow": if j.workflow_name.is_empty() { wf.clone() } else { j.workflow_name.clone() },
                "name": j.name, "labels": j.labels, "conclusion": j.conclusion,
                "created_micros": micros(created),
                "started_micros": started.map(micros),
                "completed_micros": micros(done),
            }));
            for s in &j.steps {
                f.steps.push(json!({
                    "job_id": j.id, "number": s.number, "name": s.name,
                    "conclusion": s.conclusion,
                    "started_micros": s.started_at.as_deref().and_then(epoch).map(micros),
                    "completed_micros": s.completed_at.as_deref().and_then(epoch).map(micros),
                }));
            }
        }
        if run_is_in_window
            && let (Some(c), Some(u)) = (epoch(&run.created_at), epoch(&run.updated_at))
        {
            f.runs.push(json!({
                "run_id": run.id, "workflow": wf, "event": run.event,
                "head_sha": run.head_sha, "conclusion": run.conclusion,
                "created_micros": micros(c), "updated_micros": micros(u),
            }));
        }
    }
    Ok(f)
}

/// POST the facts and return the daemon's reply.
fn post(url: &str, tenant: &str, token: &str, body: &str) -> Result<(u32, String)> {
    let mut child = Command::new("curl")
        .args([
            "-sS",
            "-m",
            "60",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-H",
            &format!("Authorization: Bearer {token}"),
            "--data-binary",
            "@-",
            "-w",
            "\n%{http_code}",
            &format!("{}/v1/{tenant}/ci-facts", url.trim_end_matches('/')),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("run curl (is it installed?)")?;
    use std::io::Write as _;
    child
        .stdin
        .take()
        .context("curl stdin")?
        .write_all(body.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("curl failed: {}", out.status);
    }
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let (reply, code) = text.rsplit_once('\n').unwrap_or(("", text.as_str()));
    Ok((code.trim().parse().unwrap_or(0), reply.to_string()))
}

/// `cargo xtask ci-facts ingest`.
///
/// **The non-vacuity floor is the point of the exit codes.** An empty fact table answers every
/// question with a confident zero, so "the window had no jobs" must not look like "the ingest
/// worked". A window that produced nothing exits 3 and says which window it was; the caller — a
/// cron, usually — can then tell a quiet fleet from a broken puller, which is the distinction
/// `.github/workflows/ci-metrics.yml` spent six silent runs unable to make.
pub fn ingest(
    since_min: u64,
    url: Option<String>,
    tenant: String,
    dry_run: bool,
) -> Result<Outcome> {
    let now = now_secs();
    let window_start = now - i64::try_from(since_min.saturating_mul(60)).unwrap_or(i64::MAX);
    let f = pull(window_start, now, &gh_api)?;

    let window = format!("{}..{}", rfc3339(window_start), rfc3339(now));
    if dry_run {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "runs": f.runs, "jobs": f.jobs, "steps": f.steps
            }))?
        );
        eprintln!(
            "ci-facts: window {window} — {} run(s), {} job(s), {} step(s); not posted (--dry-run)",
            f.runs.len(),
            f.jobs.len(),
            f.steps.len()
        );
        return Ok(Outcome::DryRun);
    }
    if f.is_empty() {
        eprintln!(
            "ci-facts: window {window} produced NO terminal jobs. That is either a quiet fleet or \
             a broken puller, and this command cannot tell them apart — it refuses to report \
             success so the difference stays visible."
        );
        return Ok(Outcome::Empty);
    }

    let url = url
        .or_else(|| std::env::var("GATEHOUSE_URL").ok())
        .context("no --url and no $GATEHOUSE_URL: there is nowhere to put these facts")?;
    let token = std::env::var("GATEHOUSE_TOKEN")
        .context("$GATEHOUSE_TOKEN is not set: /v1/{tenant}/ci-facts is an operator route")?;
    let body = serde_json::to_string(&json!({
        "runs": f.runs, "jobs": f.jobs, "steps": f.steps
    }))?;
    let (code, reply) = post(&url, &tenant, &token, &body)?;
    if code != 200 {
        bail!("ci-facts: HTTP {code} from {url}: {reply}");
    }
    println!(
        "ci-facts: window {window} — posted {} run(s), {} job(s), {} step(s); stored {reply}",
        f.runs.len(),
        f.jobs.len(),
        f.steps.len()
    );
    Ok(Outcome::Posted)
}

/// How the ingest ended. Named rather than a bare `()` so the caller's exit code is a decision
/// made here and not a boolean unpacked at the call site — `self_pin::Outcome`'s shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Posted,
    DryRun,
    Empty,
}

impl Outcome {
    pub fn exit_code(self) -> i32 {
        match self {
            Outcome::Posted | Outcome::DryRun => 0,
            Outcome::Empty => 3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gh_actions::fixture_name;

    /// The recorded window: `[2026-09-10T10:00:00Z, 2026-09-10T11:00:00Z)`. Fixed, because the
    /// windowing is the whole judgement in `pull` and a window that moves with the wall clock
    /// cannot be asserted about.
    const START: i64 = 1_789_034_400;
    const HOUR: i64 = 3_600;

    fn recorded(path: &str) -> Result<String> {
        let p = format!(
            "{}/tests/fixtures/gh-actions/{}",
            env!("CARGO_MANIFEST_DIR"),
            fixture_name(path)
        );
        std::fs::read_to_string(&p).with_context(|| format!("no recorded response at {p}"))
    }

    fn window(from: i64, to: i64) -> Facts {
        pull(from, to, &recorded).expect("pull the recorded window")
    }

    #[test]
    fn a_window_yields_its_terminal_jobs_their_steps_and_the_runs_that_own_them() {
        let f = window(START, START + HOUR);
        // The fixture holds four jobs: three terminal, one still queued.
        assert_eq!(f.jobs.len(), 3, "{:?}", f.jobs);
        assert_eq!(f.runs.len(), 2);
        assert_eq!(f.steps.len(), 10);
        // Every job carries GitHub's own id. Grouping by NAME is enough to summarise and not
        // enough to store: two jobs in one window can share a name.
        let mut ids: Vec<u64> = f
            .jobs
            .iter()
            .map(|j| j["job_id"].as_u64().unwrap())
            .collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![1, 2, 4]);
    }

    /// **A job still in flight is not a fact.** It has no `completed_at`, so `completed - started`
    /// is undefined and a row for it would have to invent one. It is skipped and re-read next
    /// window, which is what makes re-ingesting a window a no-op at the other end.
    #[test]
    fn a_job_that_has_not_finished_is_not_written() {
        let f = window(START, START + HOUR);
        assert!(
            f.jobs.iter().all(|j| j["job_id"].as_u64() != Some(3)),
            "job 3 is queued and must not be a fact: {:?}",
            f.jobs
        );
    }

    /// **The check that `status == "completed"` is load-bearing, added because it was not.**
    /// Deleting that guard changed no test: job 3 is also excluded by having no `completed_at`,
    /// so the terminal rule was being enforced by a coincidence. A job BEING RE-RUN is the case
    /// where the two disagree — GitHub flips `status` back to `in_progress` and leaves the
    /// previous attempt's `completed_at` in place — and taking it would write a row for a job
    /// that is about to produce a different answer, twice, with the first one wrong.
    #[test]
    fn a_job_being_re_run_carries_a_stale_completion_and_is_still_not_a_fact() {
        let f = window(START, START + HOUR);
        assert!(
            f.jobs.iter().all(|j| j["job_id"].as_u64() != Some(5)),
            "job 5 is in_progress with a stale completed_at and must not be a fact: {:?}",
            f.jobs
        );
        assert!(
            f.runs.iter().all(|r| r["run_id"].as_u64() != Some(900_003)),
            "and its run has nothing in the window either: {:?}",
            f.runs
        );
    }

    /// **A failed job IS a fact.** `status == "completed"` is GitHub's terminal marker and covers
    /// failed, cancelled and skipped; `conclusion` says which. Keeping only the successes would
    /// answer "how long does CI take" with the runs that worked.
    #[test]
    fn a_failed_job_is_a_fact_and_says_so() {
        let f = window(START, START + HOUR);
        let failed: Vec<&Value> = f
            .jobs
            .iter()
            .filter(|j| j["conclusion"] == "failure")
            .collect();
        assert_eq!(failed.len(), 1, "{:?}", f.jobs);
        assert_eq!(failed[0]["name"], "ledger");
    }

    /// Micros, because that is the unit every clock in gatehouse's store is kept in, and a
    /// seconds-vs-micros mix-up is a factor of a million that looks like a plausible number.
    #[test]
    fn clocks_arrive_in_microseconds() {
        let f = window(START, START + HOUR);
        let build = f
            .jobs
            .iter()
            .find(|j| j["name"] == "build")
            .expect("the build job");
        let (c, s, d) = (
            build["created_micros"].as_u64().unwrap(),
            build["started_micros"].as_u64().unwrap(),
            build["completed_micros"].as_u64().unwrap(),
        );
        // 2026-09-10T10:00:00Z created, +3m25s started, +21m40s completed.
        assert_eq!(s - c, 205 * 1_000_000, "the queue wait, in micros");
        assert_eq!(d - s, 1_095 * 1_000_000, "the run time, in micros");
    }

    /// The window is half-open on COMPLETION. A job finishing exactly at `now` belongs to the
    /// next window, or two adjacent ingests both claim it and the pin over the pair is wrong by
    /// one job in a way nothing would notice.
    #[test]
    fn the_window_is_half_open_and_a_job_lands_in_exactly_one_of_two_adjacent_ones() {
        // The `fmt` job completes at 10:02:10 and `build` at 10:21:40.
        let early = window(START, START + 130);
        assert_eq!(early.jobs.len(), 0, "10:02:10 is not < 10:02:10");
        let inclusive = window(START, START + 131);
        assert_eq!(inclusive.jobs.len(), 1);
        assert_eq!(inclusive.jobs[0]["name"], "fmt");
    }

    /// A run is written only when one of ITS jobs is in the window. A run whose jobs all finished
    /// elsewhere is not part of this window's story, and writing it would make `ci_run` a table
    /// of everything GitHub mentioned rather than of what was measured.
    #[test]
    fn a_run_with_no_job_in_the_window_is_not_written() {
        let only_fmt = window(START, START + 131);
        assert_eq!(only_fmt.runs.len(), 1);
        assert_eq!(only_fmt.runs[0]["run_id"], 900_001);
    }

    /// An empty window is not an error and not a success. `Outcome::Empty` exits 3 so a cron can
    /// tell a quiet fleet from a broken puller — the distinction `.github/workflows/ci-metrics.yml`
    /// spent six silent runs unable to make.
    #[test]
    fn the_exit_codes_keep_an_empty_window_distinguishable() {
        assert_eq!(Outcome::Posted.exit_code(), 0);
        assert_eq!(Outcome::DryRun.exit_code(), 0);
        assert_eq!(Outcome::Empty.exit_code(), 3);
    }
}
