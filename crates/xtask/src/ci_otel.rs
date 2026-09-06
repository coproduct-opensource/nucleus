//! `cargo xtask ci-otel` — GitHub-side CI throughput as OpenTelemetry metrics.
//!
//! The runner side of CI (queued jobs, busy runners, pod start-up) is what
//! the actions-runner-controller listeners already export to Prometheus. The
//! GitHub side — how long each job WAITED for a runner, how long it ran, how
//! many landed per conclusion, how deep the merge queue is — only exists in
//! the Actions API. This pulls the jobs that completed in a window and pushes
//! them to an OTLP/HTTP endpoint as histograms and counters, so both halves
//! land on the same dashboard (k8s/ci-metrics).
//!
//! Metrics (all with unit `s` where a duration):
//!   * `ci.job.queue_wait`  histogram  {workflow, runner, event}
//!     started_at − created_at: time waiting for a runner
//!   * `ci.job.duration`    histogram  {workflow, job_name, runner, event}
//!     (`job_name`, not `job`: Prometheus reserves `job` for service.name)
//!     completed_at − started_at
//!   * `ci.job.completed`   sum (delta) {workflow, runner, event, conclusion}
//!   * `ci.workflow.duration` histogram {workflow, event}
//!     run created → run updated, for runs that completed in the window
//!   * `ci.merge_queue.depth`  gauge  — entries in the main merge queue now
//!   * `ci.runs.queued` / `ci.runs.in_progress`  gauges — workflow runs now
//!
//! Delta temporality: each invocation reports the window it saw and nothing
//! else, and the collector's `deltatocumulative` processor turns that into the
//! cumulative series Prometheus wants. The window is `--since` minutes back
//! from now; a job is in the window when its `completed_at` is. Run it from a
//! schedule with `--since` equal to the schedule period (small drift at the
//! edges is accepted: this is a throughput dashboard, not an audit log).
//!
//! Usage: `cargo xtask ci-otel [--since MIN] [--endpoint URL] [--dry-run]`
//! Endpoint default: `$OTEL_EXPORTER_OTLP_ENDPOINT`, else the in-cluster
//! collector `http://otel-collector.ci-metrics.svc.cluster.local:4318`.
//! No OTel SDK: the OTLP/HTTP JSON encoding is small enough to write by hand,
//! and xtask stays a `gh`+`curl` tool with no network crates.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const REPO: &str = "coproduct-opensource/nucleus";
const DEFAULT_ENDPOINT: &str = "http://otel-collector.ci-metrics.svc.cluster.local:4318";

/// Seconds boundaries shared by every duration histogram: 5 s to 2 h.
const BOUNDS: &[f64] = &[
    5.0, 10.0, 20.0, 30.0, 60.0, 120.0, 180.0, 300.0, 600.0, 900.0, 1200.0, 1800.0, 2700.0, 3600.0,
    5400.0, 7200.0,
];

#[derive(Deserialize)]
struct RunList {
    workflow_runs: Vec<Run>,
}

#[derive(Deserialize, Clone)]
struct Run {
    id: u64,
    name: Option<String>,
    event: String,
    status: String,
    created_at: String,
    updated_at: String,
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

fn now_secs() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
    .unwrap_or(i64::MAX)
}

/// RFC 3339 `…Z` for a Unix time, whole seconds. Inverse of
/// [`crate::ci_timings::epoch`] (civil-from-days, Howard Hinnant).
fn rfc3339(secs: i64) -> String {
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

/// One histogram series: delta counts per bucket for one attribute set.
#[derive(Default, Clone)]
struct Hist {
    count: u64,
    sum: f64,
    min: f64,
    max: f64,
    buckets: Vec<u64>, // len = BOUNDS.len() + 1
}

impl Hist {
    fn observe(&mut self, v: f64) {
        if self.buckets.is_empty() {
            self.buckets = vec![0; BOUNDS.len() + 1];
            self.min = v;
            self.max = v;
        }
        self.count += 1;
        self.sum += v;
        self.min = self.min.min(v);
        self.max = self.max.max(v);
        let idx = BOUNDS.iter().position(|b| v <= *b).unwrap_or(BOUNDS.len());
        self.buckets[idx] += 1;
    }
}

type Attrs = Vec<(&'static str, String)>;

fn attrs_json(attrs: &Attrs) -> Value {
    Value::Array(
        attrs
            .iter()
            .map(|(k, v)| json!({"key": k, "value": {"stringValue": v}}))
            .collect(),
    )
}

/// The runner label that routed the job: the first non-generic one.
fn runner_of(labels: &[String]) -> String {
    labels
        .iter()
        .find(|l| !matches!(l.as_str(), "self-hosted" | "linux" | "x64" | "arm64"))
        .cloned()
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn ci_otel(since_min: u64, endpoint: Option<String>, dry_run: bool) -> Result<()> {
    let endpoint = endpoint
        .or_else(|| std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok())
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
    let now = now_secs();
    let window_start = now - i64::try_from(since_min * 60).unwrap_or(i64::MAX);
    let start_ns = format!("{}", window_start.saturating_mul(1_000_000_000));
    let now_ns = format!("{}", now.saturating_mul(1_000_000_000));

    // Runs updated since the window opened (a run's updated_at moves when a job
    // completes), any status; jobs are filtered on completed_at below.
    let since = rfc3339(window_start - 3600); // generous: long runs update late
    let runs: RunList = serde_json::from_str(&gh_api(&format!(
        "repos/{REPO}/actions/runs?created=>={since}&per_page=100"
    ))?)
    .context("parse run list")?;

    let mut queue_wait: BTreeMap<Attrs, Hist> = BTreeMap::new();
    let mut duration: BTreeMap<Attrs, Hist> = BTreeMap::new();
    let mut completed: BTreeMap<Attrs, u64> = BTreeMap::new();
    let mut wf_duration: BTreeMap<Attrs, Hist> = BTreeMap::new();
    let mut runs_queued = 0u64;
    let mut runs_in_progress = 0u64;
    let mut jobs_seen = 0usize;

    for run in &runs.workflow_runs {
        match run.status.as_str() {
            "queued" => runs_queued += 1,
            "in_progress" => runs_in_progress += 1,
            _ => {}
        }
        let wf = run.name.clone().unwrap_or_default();
        if run.status == "completed" {
            if let (Some(c), Some(u)) = (
                crate::ci_timings::epoch(&run.created_at),
                crate::ci_timings::epoch(&run.updated_at),
            ) && u > window_start
                && u <= now
            {
                wf_duration
                    .entry(vec![("workflow", wf.clone()), ("event", run.event.clone())])
                    .or_default()
                    .observe((u - c).max(0) as f64);
            }
        }
        let list: JobList = serde_json::from_str(&gh_api(&format!(
            "repos/{REPO}/actions/runs/{}/jobs?per_page=100",
            run.id
        ))?)
        .with_context(|| format!("parse jobs of run {}", run.id))?;
        for j in list.jobs {
            if j.status != "completed" {
                continue;
            }
            let (Some(created), Some(started), Some(done)) = (
                crate::ci_timings::epoch(&j.created_at),
                j.started_at.as_deref().and_then(crate::ci_timings::epoch),
                j.completed_at.as_deref().and_then(crate::ci_timings::epoch),
            ) else {
                continue;
            };
            if done <= window_start || done > now {
                continue;
            }
            jobs_seen += 1;
            let runner = runner_of(&j.labels);
            let conclusion = j.conclusion.clone().unwrap_or_else(|| "unknown".into());
            queue_wait
                .entry(vec![
                    ("workflow", wf.clone()),
                    ("runner", runner.clone()),
                    ("event", run.event.clone()),
                ])
                .or_default()
                .observe((started - created).max(0) as f64);
            duration
                .entry(vec![
                    ("workflow", wf.clone()),
                    ("job_name", j.name.clone()),
                    ("runner", runner.clone()),
                    ("event", run.event.clone()),
                ])
                .or_default()
                .observe((done - started).max(0) as f64);
            *completed
                .entry(vec![
                    ("workflow", wf.clone()),
                    ("runner", runner),
                    ("event", run.event.clone()),
                    ("conclusion", conclusion),
                ])
                .or_default() += 1;
        }
    }

    let mq: Value = Command::new("gh")
        .args([
            "api",
            "graphql",
            "-f",
            "query={repository(owner:\"coproduct-opensource\",name:\"nucleus\"){mergeQueue(branch:\"main\"){entries(first:1){totalCount}}}}",
        ])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| serde_json::from_slice(&o.stdout).ok())
        .unwrap_or(Value::Null);
    let mq_depth = mq["data"]["repository"]["mergeQueue"]["entries"]["totalCount"]
        .as_u64()
        .unwrap_or(0);

    let hist_metric = |name: &str, desc: &str, series: &BTreeMap<Attrs, Hist>| -> Value {
        json!({
            "name": name, "description": desc, "unit": "s",
            "histogram": {
                "aggregationTemporality": 1, // DELTA
                "dataPoints": series.iter().map(|(a, h)| json!({
                    "attributes": attrs_json(a),
                    "startTimeUnixNano": start_ns, "timeUnixNano": now_ns,
                    "count": h.count.to_string(), "sum": h.sum, "min": h.min, "max": h.max,
                    "bucketCounts": h.buckets.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                    "explicitBounds": BOUNDS,
                })).collect::<Vec<_>>(),
            }
        })
    };
    // Unit left empty on the counts: the collector's Prometheus exporter turns
    // unit "1" into a `_ratio` suffix, which a queue depth is not.
    let gauge = |name: &str, desc: &str, v: u64| -> Value {
        json!({
            "name": name, "description": desc, "unit": "",
            "gauge": {"dataPoints": [{"timeUnixNano": now_ns, "asInt": v.to_string()}]}
        })
    };
    let payload = json!({
        "resourceMetrics": [{
            "resource": {"attributes": [
                {"key": "service.name", "value": {"stringValue": "github-actions"}},
                {"key": "github.repository", "value": {"stringValue": REPO}},
            ]},
            "scopeMetrics": [{
                "scope": {"name": "nucleus.xtask.ci-otel"},
                "metrics": [
                    hist_metric("ci.job.queue_wait", "seconds a job waited for a runner (started_at - created_at)", &queue_wait),
                    hist_metric("ci.job.duration", "seconds a job ran (completed_at - started_at)", &duration),
                    hist_metric("ci.workflow.duration", "seconds from run creation to completion", &wf_duration),
                    json!({
                        "name": "ci.job.completed", "description": "jobs completed in the window, by conclusion", "unit": "",
                        "sum": {"aggregationTemporality": 1, "isMonotonic": true,
                            "dataPoints": completed.iter().map(|(a, n)| json!({
                                "attributes": attrs_json(a),
                                "startTimeUnixNano": start_ns, "timeUnixNano": now_ns,
                                "asInt": n.to_string(),
                            })).collect::<Vec<_>>()}
                    }),
                    gauge("ci.merge_queue.depth", "entries in the main merge queue", mq_depth),
                    gauge("ci.runs.queued", "workflow runs queued now", runs_queued),
                    gauge("ci.runs.in_progress", "workflow runs in progress now", runs_in_progress),
                ]
            }]
        }]
    });

    eprintln!(
        "ci-otel: window {}..{} — {} runs seen, {} jobs completed in window, {} job series, merge queue depth {}, runs queued {} / in progress {}",
        rfc3339(window_start),
        rfc3339(now),
        runs.workflow_runs.len(),
        jobs_seen,
        duration.len(),
        mq_depth,
        runs_queued,
        runs_in_progress
    );
    if dry_run {
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }
    let body = serde_json::to_string(&payload)?;
    let out = Command::new("curl")
        .args([
            "-sS",
            "-m",
            "20",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "--data-binary",
            "@-",
            "-w",
            "%{http_code}",
            "-o",
            "/dev/null",
            &format!("{}/v1/metrics", endpoint.trim_end_matches('/')),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawn curl")?;
    {
        use std::io::Write as _;
        let mut stdin = out.stdin.as_ref().context("curl stdin")?;
        stdin.write_all(body.as_bytes())?;
    }
    let done = out.wait_with_output()?;
    let code = String::from_utf8_lossy(&done.stdout).trim().to_string();
    if !done.status.success() || !code.starts_with('2') {
        bail!(
            "OTLP export to {endpoint} failed: http {code} {}",
            String::from_utf8_lossy(&done.stderr).trim()
        );
    }
    eprintln!("ci-otel: exported to {endpoint} (http {code})");
    Ok(())
}
