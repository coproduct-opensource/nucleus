//! The GitHub Actions API, pulled once.
//!
//! `ci_timings` and `ci_otel` were written three weeks apart and each grew its own copy of the
//! same four things: the `Run`/`Job`/`Step` shapes, `gh api`, the RFC 3339 parser, and its
//! inverse. Two copies of a parser is two answers to "what is a job's queue wait", and the
//! divergence is invisible until the numbers disagree. `ci-facts ingest` would have been the
//! third copy; this module is what it calls instead.
//!
//! **The structs are the UNION of what the callers read, and nothing more.** All three hit the
//! same endpoints, so every field is present in every response; a caller that does not need
//! `steps` simply ignores it. When this module was extracted it carried a job's `id`, a step's
//! `number` and a run's `head_sha` for a caller that did not exist yet, and the compiler was
//! right to call them dead: they came out, and came back with `ci_facts`, which is the first
//! thing here that identifies a row rather than summarising one.
//!
//! The `Option` fields are the ones GitHub really does omit (a job that never started has no
//! `started_at`); `#[serde(default)]` covers the two the *list* endpoints leave out.
//!
//! **Fixtures.** `gh_api` reads from a directory instead of the network when `GH_API_FIXTURES`
//! names one. That is not a testing convenience bolted on: `gh` needs an authenticated CLI and a
//! network, and without it none of this is runnable or reviewable off a runner. A recorded
//! response is also the only way to check that a refactor of these two commands changed no
//! output, which is the claim `crates/xtask/tests/gh_actions.rs` makes.

use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

/// The repository every puller here reads. Not a parameter: these commands report on nucleus's
/// own CI and a flag would only invite pointing them somewhere the numbers mean nothing.
pub const REPO: &str = "coproduct-opensource/nucleus";

/// `GET …/actions/runs` — the envelope.
#[derive(Deserialize)]
pub struct RunList {
    pub workflow_runs: Vec<Run>,
}

/// One workflow run.
#[derive(Deserialize, Clone)]
pub struct Run {
    pub id: u64,
    pub name: Option<String>,
    pub event: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    /// The commit the run is about. `ci_facts` keys a run to a tree by it; the two reporters do
    /// not name it because a report is already scoped to one commit or one window.
    #[serde(default)]
    pub head_sha: String,
    #[serde(default)]
    pub conclusion: Option<String>,
}

/// `GET …/actions/runs/{id}/jobs` — the envelope.
#[derive(Deserialize)]
pub struct JobList {
    pub jobs: Vec<Job>,
}

/// One job of one run.
///
/// `workflow_name` is `#[serde(default)]` because the runs-scoped jobs endpoint omits it on older
/// responses; both callers fill it in from the enclosing run when it comes back empty.
#[derive(Deserialize, Clone)]
pub struct Job {
    /// GitHub's own identifier. The two reporters group by NAME, which is enough to summarise
    /// and not enough to store: two jobs in one window can share a name.
    #[serde(default)]
    pub id: u64,
    pub name: String,
    pub status: String,
    pub conclusion: Option<String>,
    pub labels: Vec<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    #[serde(default)]
    pub steps: Vec<Step>,
    #[serde(default)]
    pub workflow_name: String,
}

/// One step of one job.
#[derive(Deserialize, Clone)]
pub struct Step {
    /// The step's position in its job. Names repeat within a job (`Post …`); positions do not.
    #[serde(default)]
    pub number: u32,
    pub name: String,
    pub conclusion: Option<String>,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
}

/// Where a recorded response for `path` lives under `dir`.
///
/// The path is the cache key, so it has to survive being a filename: `/` becomes `_`, and every
/// character outside `[A-Za-z0-9._-]` becomes `_` too. Distinct API paths can therefore collide
/// in principle; in practice the paths these commands build differ in their identifiers, and a
/// collision is a missing-file error rather than a wrong answer because the recorder uses the
/// same function.
pub fn fixture_name(path: &str) -> String {
    let mut s: String = path
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    s.push_str(".json");
    s
}

/// `gh api <path>`, or the recorded response when `GH_API_FIXTURES` names a directory.
pub fn gh_api(path: &str) -> Result<String> {
    if let Some(dir) = std::env::var_os("GH_API_FIXTURES") {
        let file = PathBuf::from(dir).join(fixture_name(path));
        return std::fs::read_to_string(&file).with_context(|| {
            format!(
                "GH_API_FIXTURES is set, so `gh api {path}` must be recorded at {}",
                file.display()
            )
        });
    }
    let out = Command::new("gh")
        .args(["api", path])
        .output()
        .context("run gh api (is the GitHub CLI installed and authenticated?)")?;
    if !out.status.success() {
        bail!(
            "gh api {path} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8(out.stdout)?)
}

/// Seconds since the Unix epoch for an RFC 3339 UTC timestamp (`…Z`).
/// Hand-rolled to keep xtask dependency-free of a time crate.
pub fn epoch(ts: &str) -> Option<i64> {
    let ts = ts.strip_suffix('Z')?;
    let (date, time) = ts.split_once('T')?;
    let mut d = date.split('-').map(|s| s.parse::<i64>());
    let (y, m, day) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
    let mut t = time.split(':');
    let (h, mi) = (
        t.next()?.parse::<i64>().ok()?,
        t.next()?.parse::<i64>().ok()?,
    );
    // Whole seconds only: the fraction is noise at the minute granularity reported.
    let s = t.next()?.split('.').next()?.parse::<i64>().ok()?;
    // Days from civil (Howard Hinnant's algorithm).
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + s)
}

/// RFC 3339 `…Z` for a Unix time, whole seconds. Inverse of [`epoch`]
/// (civil-from-days, Howard Hinnant).
pub fn rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}
