//! `cargo xtask ci-timings` — where does a commit's CI time go?
//!
//! Pulls every workflow run for one commit through `gh api`, then reports:
//!   * per runner label: job count, run-time and queue-wait distributions;
//!   * the wall clock (first job created → last job completed) and the
//!     critical path (the job that finished last, and why);
//!   * the longest jobs with their two longest steps;
//!   * setup overhead (checkout / toolchain / cache steps) vs. real work.
//!
//! Numbers, not impressions: this is what a CI-optimisation change has to
//! move. Run it before and after, on the same kind of commit.
//!
//! Usage: `cargo xtask ci-timings [--sha <sha>] [--top N] [--json]`
//! (default sha = HEAD; needs `gh` authenticated for the repo).

use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::process::Command;

const REPO: &str = "coproduct-opensource/nucleus";

#[derive(Deserialize)]
struct RunList {
    workflow_runs: Vec<Run>,
}

#[derive(Deserialize, Clone)]
struct Run {
    id: u64,
    name: Option<String>,
    event: String,
}

#[derive(Deserialize)]
struct JobList {
    jobs: Vec<Job>,
}

#[derive(Deserialize, Clone)]
struct Job {
    name: String,
    status: String,
    conclusion: Option<String>,
    labels: Vec<String>,
    created_at: String,
    started_at: Option<String>,
    completed_at: Option<String>,
    steps: Vec<Step>,
    #[serde(default)]
    workflow_name: String,
}

#[derive(Deserialize, Clone)]
struct Step {
    name: String,
    conclusion: Option<String>,
    started_at: Option<String>,
    completed_at: Option<String>,
}

/// Seconds since the Unix epoch for an RFC 3339 UTC timestamp (`…Z`).
/// Hand-rolled to keep xtask dependency-free of a time crate.
fn epoch(ts: &str) -> Option<i64> {
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

fn gh_api(path: &str) -> Result<String> {
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

fn head_sha() -> Result<String> {
    let out = Command::new("git").args(["rev-parse", "HEAD"]).output()?;
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

/// The `pct`-th percentile (0–100) of ascending seconds — nearest-rank.
fn percentile(sorted: &[i64], pct: usize) -> i64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (sorted.len() * pct).div_ceil(100);
    sorted[idx.clamp(1, sorted.len()) - 1]
}

fn median(sorted: &[i64]) -> i64 {
    percentile(sorted, 50)
}

/// Seconds as minutes with one decimal. Durations fit an `i32` comfortably
/// (an `i32` of seconds is 68 years), so the widening to `f64` is exact.
fn mins(secs: i64) -> String {
    let secs = i32::try_from(secs).unwrap_or(i32::MAX);
    format!("{:.1}m", f64::from(secs) / 60.0)
}

const SETUP_MARKERS: &[&str] = &[
    "Set up job",
    "checkout",
    "toolchain",
    "Cache",
    "cache",
    "Install",
    "elan",
    "Fetch Mathlib",
    "Complete job",
    "Post ",
    "Is this change in scope",
    "Detect",
];

pub fn ci_timings(sha: Option<String>, top: usize, json: bool) -> Result<()> {
    let sha = match sha {
        Some(s) => s,
        None => head_sha()?,
    };
    let runs: RunList = serde_json::from_str(&gh_api(&format!(
        "repos/{REPO}/actions/runs?head_sha={sha}&per_page=100"
    ))?)
    .context("parse run list")?;
    if runs.workflow_runs.is_empty() {
        bail!("no workflow runs for {sha}");
    }
    let mut jobs: Vec<Job> = Vec::new();
    for run in &runs.workflow_runs {
        let list: JobList = serde_json::from_str(&gh_api(&format!(
            "repos/{REPO}/actions/runs/{}/jobs?per_page=100",
            run.id
        ))?)
        .with_context(|| format!("parse jobs of run {}", run.id))?;
        for mut j in list.jobs {
            if j.workflow_name.is_empty() {
                j.workflow_name = run.name.clone().unwrap_or_default();
            }
            jobs.push(j);
        }
    }
    if json {
        // Raw-ish dump for further analysis: one object per job.
        let v: Vec<serde_json::Value> = jobs
            .iter()
            .map(|j| {
                serde_json::json!({
                    "workflow": j.workflow_name, "job": j.name, "labels": j.labels,
                    "status": j.status, "conclusion": j.conclusion,
                    "created": j.created_at, "started": j.started_at, "completed": j.completed_at,
                    "steps": j.steps.iter().map(|s| serde_json::json!({
                        "name": s.name, "conclusion": s.conclusion,
                        "started": s.started_at, "completed": s.completed_at})).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }

    let events: BTreeMap<String, usize> =
        runs.workflow_runs.iter().fold(BTreeMap::new(), |mut m, r| {
            *m.entry(r.event.clone()).or_default() += 1;
            m
        });
    println!("# CI timings for {sha}");
    println!(
        "runs: {} ({}), jobs: {}",
        runs.workflow_runs.len(),
        events
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", "),
        jobs.len()
    );
    let mut concl: BTreeMap<String, usize> = BTreeMap::new();
    for j in &jobs {
        *concl
            .entry(j.conclusion.clone().unwrap_or_else(|| j.status.clone()))
            .or_default() += 1;
    }
    println!(
        "conclusions: {}",
        concl
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", ")
    );

    let done: Vec<&Job> = jobs
        .iter()
        .filter(|j| j.started_at.is_some() && j.completed_at.is_some())
        .collect();
    let t0 = jobs
        .iter()
        .filter_map(|j| epoch(&j.created_at))
        .min()
        .ok_or_else(|| anyhow!("no timestamps"))?;
    let tend = done
        .iter()
        .filter_map(|j| epoch(j.completed_at.as_deref()?))
        .max()
        .unwrap_or(t0);
    println!(
        "wall: {} (first job created → last job completed); still pending: {}",
        mins(tend - t0),
        jobs.len() - done.len()
    );
    if let Some(last) = done
        .iter()
        .max_by_key(|j| epoch(j.completed_at.as_deref().unwrap_or("")).unwrap_or(0))
    {
        let c = epoch(&last.created_at).unwrap_or(t0);
        let s = epoch(last.started_at.as_deref().unwrap_or("")).unwrap_or(c);
        let e = epoch(last.completed_at.as_deref().unwrap_or("")).unwrap_or(s);
        println!(
            "critical path: {} / {} [{}] — created +{}, queued {}, ran {}",
            last.workflow_name,
            last.name,
            last.labels.join(","),
            mins(c - t0),
            mins(s - c),
            mins(e - s)
        );
    }

    println!("\n## per runner label (successful jobs)");
    println!(
        "| label | jobs | run median | run p90 | run max | run sum | queue median | queue p90 | queue max |"
    );
    println!("|---|---|---|---|---|---|---|---|---|");
    let mut labels: Vec<String> = jobs.iter().map(|j| j.labels.join(",")).collect();
    labels.sort();
    labels.dedup();
    for lab in labels {
        let rs: Vec<&&Job> = done
            .iter()
            .filter(|j| j.labels.join(",") == lab && j.conclusion.as_deref() == Some("success"))
            .collect();
        if rs.is_empty() {
            continue;
        }
        let mut d: Vec<i64> = rs
            .iter()
            .map(|j| {
                epoch(j.completed_at.as_deref().unwrap()).unwrap_or(0)
                    - epoch(j.started_at.as_deref().unwrap()).unwrap_or(0)
            })
            .collect();
        let mut q: Vec<i64> = rs
            .iter()
            .map(|j| {
                epoch(j.started_at.as_deref().unwrap()).unwrap_or(0)
                    - epoch(&j.created_at).unwrap_or(0)
            })
            .collect();
        d.sort_unstable();
        q.sort_unstable();
        println!(
            "| {lab} | {} | {} | {} | {} | {} | {} | {} | {} |",
            rs.len(),
            mins(median(&d)),
            mins(percentile(&d, 90)),
            mins(*d.last().unwrap()),
            mins(d.iter().sum()),
            mins(median(&q)),
            mins(percentile(&q, 90)),
            mins(*q.last().unwrap())
        );
    }

    let step_secs = |s: &Step| -> Option<i64> {
        Some(epoch(s.completed_at.as_deref()?)? - epoch(s.started_at.as_deref()?)?)
    };
    println!("\n## longest {top} jobs (run time; two longest steps)");
    let mut by_len: Vec<&&Job> = done.iter().collect();
    by_len.sort_by_key(|j| {
        -(epoch(j.completed_at.as_deref().unwrap()).unwrap_or(0)
            - epoch(j.started_at.as_deref().unwrap()).unwrap_or(0))
    });
    for j in by_len.iter().take(top) {
        let d = epoch(j.completed_at.as_deref().unwrap()).unwrap_or(0)
            - epoch(j.started_at.as_deref().unwrap()).unwrap_or(0);
        let mut steps: Vec<(String, i64)> = j
            .steps
            .iter()
            .filter_map(|s| Some((s.name.clone(), step_secs(s)?)))
            .collect();
        steps.sort_by_key(|(_, secs)| std::cmp::Reverse(*secs));
        let top2 = steps
            .iter()
            .take(2)
            .map(|(n, s)| format!("{} {}", n.chars().take(40).collect::<String>(), mins(*s)))
            .collect::<Vec<_>>()
            .join("; ");
        println!(
            "- {} [{}] {} / {} :: {}",
            mins(d),
            j.labels.join(","),
            j.workflow_name,
            j.name,
            top2
        );
    }

    let (mut setup, mut work) = (Vec::new(), Vec::new());
    for j in &done {
        if j.conclusion.as_deref() != Some("success") {
            continue;
        }
        let (mut s_t, mut w_t) = (0i64, 0i64);
        for s in &j.steps {
            let Some(secs) = step_secs(s) else { continue };
            if SETUP_MARKERS.iter().any(|m| s.name.contains(m)) {
                s_t += secs;
            } else {
                w_t += secs;
            }
        }
        setup.push(s_t);
        work.push(w_t);
    }
    setup.sort_unstable();
    work.sort_unstable();
    println!(
        "\n## setup vs work over {} successful jobs\nsetup: median {}s, total {}; work: median {}s, total {}",
        setup.len(),
        median(&setup),
        mins(setup.iter().sum()),
        median(&work),
        mins(work.iter().sum())
    );
    let failed: Vec<String> = jobs
        .iter()
        .filter(|j| j.conclusion.as_deref() == Some("failure"))
        .map(|j| format!("{} / {}", j.workflow_name, j.name))
        .collect();
    if !failed.is_empty() {
        println!("\n## failed\n- {}", failed.join("\n- "));
    }
    Ok(())
}
