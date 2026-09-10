//! `cargo xtask ci-ejections` — how often does a merge-queue entry eject, and on what?
//!
//! This is the number that decides a batch size. Batching multiplies the cost of a red: one
//! failing entry takes every PR batched with it. The published thresholds are a failure rate
//! under 2 % for batches of 5–10 and over 5 % for batches of 2–3, so a queue that does not know
//! its own ejection rate cannot choose one — it can only guess and find out.
//!
//! **The distinction this tool exists to enforce is `ejected` vs `in flight`.** Measured by hand
//! first, and the hand version got it wrong: an entry whose PR is not merged looks ejected, and
//! the PR sitting at position 1 building right now looks exactly the same. That one mistake moved
//! the rate from 8 % to 15 % — across the 5 % threshold that decides the batch size. So the queue
//! is consulted for what is still in it, and only the remainder can be called ejected.
//!
//! An entry is identified from its merge-group branch, `gh-readonly-queue/<base>/pr-<n>-<sha>`,
//! which is the only place the PR number and the queue base appear together.
//!
//! Usage: `cargo xtask ci-ejections [--limit N] [--json]`
//! (default limit 400 workflow runs; needs `gh` authenticated for the repo).

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

const REPO: &str = "coproduct-opensource/nucleus";

#[derive(Deserialize)]
struct RunList {
    workflow_runs: Vec<Run>,
}

#[derive(Deserialize, Clone)]
struct Run {
    head_branch: Option<String>,
    head_sha: String,
    created_at: String,
}

#[derive(Deserialize)]
struct CheckRunList {
    check_runs: Vec<CheckRun>,
}

#[derive(Deserialize, Clone)]
struct CheckRun {
    name: String,
    conclusion: Option<String>,
}

#[derive(Deserialize)]
struct Pr {
    number: u64,
    /// Present iff the PR merged. The only reliable "did this land" signal: `state` is `closed`
    /// both for a PR that merged and for one somebody closed by hand.
    merged_at: Option<String>,
}

/// What became of one merge-queue entry.
#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum Outcome {
    Merged,
    /// Left the queue without merging. Only concluded for an entry the queue no longer holds.
    Ejected,
    /// Still queued or building. NOT an ejection, and the reason this enum has three arms.
    InFlight,
}

struct Entry {
    pr: u64,
    sha: String,
    created_at: String,
    outcome: Outcome,
    /// The first REQUIRED check that failed, when one did. A non-required failure (the
    /// informational shadow gates, say) never ejects anything, so attributing an ejection to one
    /// would name the wrong cause.
    cause: Option<String>,
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

/// The PR numbers the queue holds right now. An entry in here is in flight whatever its checks
/// say, and calling it ejected is the error this tool exists to prevent.
fn queued_now() -> Result<BTreeSet<u64>> {
    let q = format!(
        r#"{{repository(owner:"{owner}",name:"{name}"){{mergeQueue(branch:"main"){{entries(first:100){{nodes{{pullRequest{{number}}}}}}}}}}}}"#,
        owner = REPO.split('/').next().unwrap_or_default(),
        name = REPO.split('/').nth(1).unwrap_or_default(),
    );
    let out = Command::new("gh")
        .args(["api", "graphql", "-f", &format!("query={q}")])
        .output()
        .context("read the live merge queue")?;
    if !out.status.success() {
        // A queue that cannot be read is not an empty queue. Refuse rather than silently
        // reclassify every in-flight entry as an ejection.
        bail!(
            "could not read the merge queue: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    Ok(v["data"]["repository"]["mergeQueue"]["entries"]["nodes"]
        .as_array()
        .map(|ns| {
            ns.iter()
                .filter_map(|n| n["pullRequest"]["number"].as_u64())
                .collect()
        })
        .unwrap_or_default())
}

/// The required contexts, so a failure can be attributed only to something that could eject.
fn required_contexts() -> BTreeSet<String> {
    std::fs::read_to_string("ci/required-checks.txt")
        .map(|s| {
            s.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

pub fn ci_ejections(limit: usize, json: bool) -> Result<()> {
    // PAGINATE, because a merge group fans out to ~31 workflow runs: one API page of 100 runs is
    // barely three entries, and three decided entries cannot support a rate at all — the first
    // run of this tool reported 0/3 and had to shout its own n. `per_page` is capped at 100 by
    // the API, so the only way to a usable window is more pages.
    let mut all: Vec<Run> = Vec::new();
    let mut page = 1u32;
    while all.len() < limit {
        let batch: RunList = serde_json::from_str(&gh_api(&format!(
            "repos/{REPO}/actions/runs?event=merge_group&per_page=100&page={page}"
        ))?)?;
        if batch.workflow_runs.is_empty() {
            break;
        }
        all.extend(batch.workflow_runs);
        page += 1;
        if page > 20 {
            break; // 2000 runs is far past any useful window; do not loop forever
        }
    }

    // One entry per (pr, sha): a merge group fans out to ~31 workflow runs that all share both.
    let mut seen: BTreeMap<(u64, String), String> = BTreeMap::new();
    for r in &all {
        let Some(b) = &r.head_branch else { continue };
        // gh-readonly-queue/<base>/pr-<n>-<basesha>
        let Some(rest) = b.rsplit_once("/pr-").map(|(_, t)| t) else {
            continue;
        };
        let Some(n) = rest.split('-').next().and_then(|d| d.parse::<u64>().ok()) else {
            continue;
        };
        seen.entry((n, r.head_sha.clone()))
            .or_insert_with(|| r.created_at.clone());
    }
    if seen.is_empty() {
        println!("no merge-group entries in the last {limit} runs — nothing to measure");
        return Ok(());
    }

    let in_queue = queued_now()?;
    let required = required_contexts();

    let mut entries = Vec::new();
    for ((pr, sha), created_at) in seen {
        let pr: Pr = serde_json::from_str(&gh_api(&format!("repos/{REPO}/pulls/{pr}"))?)?;
        let (number, merged) = (pr.number, pr.merged_at.is_some());

        // Three arms, and the middle one is the whole point: the queue is asked what it still
        // holds, and an entry it holds is in flight no matter how its checks currently read.
        let outcome = if merged {
            Outcome::Merged
        } else if in_queue.contains(&number) {
            Outcome::InFlight
        } else {
            Outcome::Ejected
        };
        let pr = number;

        // Attribute a cause only for an ejection, and only to a REQUIRED context.
        let cause = if outcome == Outcome::Ejected {
            let checks: CheckRunList = serde_json::from_str(&gh_api(&format!(
                "repos/{REPO}/commits/{sha}/check-runs?per_page=100"
            ))?)?;
            checks
                .check_runs
                .iter()
                .filter(|c| c.conclusion.as_deref() == Some("failure"))
                .find(|c| required.contains(&c.name))
                .map(|c| c.name.clone())
        } else {
            None
        };

        entries.push(Entry {
            pr,
            sha,
            created_at,
            outcome,
            cause,
        });
    }
    entries.sort_by(|a, b| a.created_at.cmp(&b.created_at));

    if json {
        for e in &entries {
            println!(
                r#"{{"pr":{},"sha":"{}","created_at":"{}","outcome":"{:?}","cause":{}}}"#,
                e.pr,
                e.sha,
                e.created_at,
                e.outcome,
                e.cause
                    .as_ref()
                    .map_or_else(|| "null".to_string(), |c| format!("{c:?}"))
            );
        }
        return Ok(());
    }

    let merged = entries
        .iter()
        .filter(|e| e.outcome == Outcome::Merged)
        .count();
    let ejected = entries
        .iter()
        .filter(|e| e.outcome == Outcome::Ejected)
        .count();
    let in_flight = entries
        .iter()
        .filter(|e| e.outcome == Outcome::InFlight)
        .count();
    let decided = merged + ejected;

    let first = entries.first().map_or("", |e| e.created_at.as_str());
    let last = entries.last().map_or("", |e| e.created_at.as_str());
    println!("# Merge-queue ejections for {REPO}");
    println!("window: {first} .. {last} ({} entries)\n", entries.len());

    println!("| PR | outcome | cause (required failure only) |");
    println!("|---|---|---|");
    for e in &entries {
        let o = match e.outcome {
            Outcome::Merged => "merged",
            Outcome::Ejected => "**ejected**",
            Outcome::InFlight => "in flight",
        };
        println!(
            "| #{} | {} | {} |",
            e.pr,
            o,
            e.cause.as_deref().unwrap_or("—")
        );
    }

    println!();
    if decided == 0 {
        println!("no DECIDED entries yet ({in_flight} in flight) — no rate to report");
        return Ok(());
    }
    #[allow(clippy::cast_precision_loss)] // counts, not money
    let rate = 100.0 * ejected as f64 / decided as f64;
    println!("merged {merged}, ejected {ejected}, in flight {in_flight} (not counted)");
    println!("ejection rate: {ejected}/{decided} = {rate:.0}% of DECIDED entries");
    println!();
    // The thresholds are the published ones; the point of printing them next to the measurement
    // is that a batch size chosen without the measurement is a guess.
    let advice = if rate < 2.0 {
        "under 2%: batches of 5-10 are the published guidance"
    } else if rate <= 5.0 {
        "2-5%: batches of 3-5"
    } else {
        "over 5%: batches of 2-3 — bisection will be common"
    };
    println!("batch-size guidance at this rate — {advice}");
    if decided < 30 {
        // Same reason as the rate above: a count of queue entries, bounded by the queue
        // and nowhere near 2^53. Bound to a local because an `allow` on a macro
        // INVOCATION does not reach a cast inside the macro's arguments -- with the
        // attribute on the `println!` the lint still fired.
        #[allow(clippy::cast_precision_loss)]
        let one_event_moves_by = 100.0 / decided as f64;
        println!(
            "CAUTION: n={decided} decided entries is thin. One event moves this by {one_event_moves_by:.0} points."
        );
    }
    Ok(())
}
