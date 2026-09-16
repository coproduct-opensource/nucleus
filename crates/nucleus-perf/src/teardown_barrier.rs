//! `nucleus-perf teardown-barrier` — cancel is a barrier, on a live node.
//!
//! **The law.** Once the node begins tearing a pod down, the guest is served
//! nothing more over the workload API. #2930 found the opposite in-process: the
//! bridge's shutdown stopped accepting connections but went on serving the ones
//! already open, so a guest was served — and minted a certificate for an identity
//! the node had just released — for the whole of teardown, which on Firecracker
//! runs the bridge shutdown first and kills the VMM last. The in-process census
//! has no VMM, no broker and no network teardown inside that window; this has all
//! three.
//!
//! **How.** The pod's workload is `nucleus-adversary-probe barrier`, which holds a
//! connection and sends `FETCH_SVID` as fast as it is answered, reconnecting if
//! closed, until it is killed. Once the node has logged enough of those commands to
//! show the guest is mid-stream, the harness cancels the pod, then reads the node's
//! own log: every command it served for the pod, and the line where the pod's
//! bridge began shutting down. The verdict is the count after that line.
//!
//! **Why the node's log, and why it needs no clock.** The guest is killed before it
//! could report, and a guest's report is a guest being believed. The node logs each
//! command it is about to serve (`workload_api_vsock` at debug) and the start of the
//! bridge's shutdown (info), in one stream, so "after" is line order, not a timestamp
//! comparison across two clocks.
//!
//! **The allowance.** A frame the node had already read when shutdown began is
//! served to completion — that is the fix's design, so a receipt mid-ship is not
//! truncated — and its log line may land after the shutdown line. So up to
//! [`IN_FLIGHT_ALLOWANCE`] commands after it still hold. The guest holds one
//! connection; the tool-proxy may hold another.
//!
//! # What live runs found (nucleus-kvm, 2026-09-16)
//!
//! - **With #2930:** held on 4 of 4 runs. The guest was served 467–917 commands
//!   before the bridge began shutting down, and 0 after.
//! - **Without it** (the bridge as it was before #2930, everything else the same):
//!   VIOLATED on 3 of 3 runs, with 8, 12 and 17 commands served after the bridge
//!   began shutting down. That is the guest being answered through the rest of
//!   teardown until the VMM was killed.
//! - **Not this law, seen on the way:** the pod reaper re-reaps an exited pod every
//!   10 s for as long as it stays registered. Each pass appends another `pod_exited`
//!   entry to the pod's lifecycle log (6 for one exit) and logs a misleading "keys
//!   have drifted apart" warning, because the identity was already released.
//!
//! # Exit status
//!
//! `0` held on every run; `1` violated on any; `2` could not look (the guest never
//! got going, the node never logged the shutdown, or a request failed).

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::node_mtls::Node;

/// Commands the node may log after the shutdown line and still hold: one frame
/// already read on each connection that could be open (the probe's and the
/// tool-proxy's).
const IN_FLIGHT_ALLOWANCE: usize = 2;

#[derive(clap::Parser)]
pub struct Args {
    /// Node base URL (mTLS).
    #[arg(long, default_value = "https://127.0.0.1:8080")]
    pub url: String,
    #[command(flatten)]
    pub tls: crate::node_mtls::NodeTls,
    /// Pod spec (YAML or JSON) whose workload is `nucleus-adversary-probe barrier`.
    #[arg(long)]
    pub spec: PathBuf,
    /// The node's log, written at debug level for `nucleus_node::workload_api_vsock`.
    #[arg(long)]
    pub node_log: PathBuf,
    #[arg(long, default_value = "3")]
    pub runs: usize,
    /// Commands the node must have served the guest before the harness cancels, so
    /// the cancel lands mid-stream rather than before the guest started.
    #[arg(long, default_value = "200")]
    pub min_before: usize,
    /// Restore the spec's scratch image from a template before every run, as
    /// `SCRATCH=TEMPLATE` — the spawn path checks the pinned scratch digest.
    #[arg(long, value_name = "SCRATCH=TEMPLATE")]
    pub fresh_scratch: Option<String>,
    /// Seconds to wait for the guest to get going.
    #[arg(long, default_value = "120")]
    pub timeout_secs: u64,
    /// Write the report here as JSON.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

/// One run's verdict, read from the node's log.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Verdict {
    Held { before: usize, after: usize },
    Violated { before: usize, after: usize },
    NotChecked(String),
}

/// The command a node log line says was served for `pod`, if it says one.
///
/// The node's shape is `workload API <COMMAND> for pod <id>`; `<COMMAND>` is the
/// wire name, upper case and underscores. Anything else naming the pod — the
/// shutdown line, "rejected command" — is not a command served.
fn command_for_pod<'a>(line: &'a str, pod: &str) -> Option<&'a str> {
    let rest = &line[line.find("workload API ")? + "workload API ".len()..];
    let (command, tail) = rest.split_once(' ')?;
    let is_wire_name =
        !command.is_empty() && command.bytes().all(|b| b.is_ascii_uppercase() || b == b'_');
    (is_wire_name && tail.trim_end() == format!("for pod {pod}")).then_some(command)
}

fn is_shutdown_for_pod(line: &str, pod: &str) -> bool {
    line.trim_end().ends_with(&format!(
        "workload API vsock bridge shutting down for pod {pod}"
    ))
}

/// A log line's message. The node logs JSON (`fields.message`); a plain-text log is
/// its own message. Matching the raw JSON line against the message's shape finds
/// nothing, and the verdict would be NOT CHECKED on every run.
fn message(line: &str) -> String {
    serde_json::from_str::<Value>(line)
        .ok()
        .and_then(|v| v.pointer("/fields/message")?.as_str().map(str::to_owned))
        .unwrap_or_else(|| line.to_owned())
}

/// The verdict for `pod` from the node log written during its run.
pub fn verdict(log: &str, pod: &str, min_before: usize) -> Verdict {
    let messages: Vec<String> = log.lines().map(message).collect();
    let lines: Vec<&str> = messages.iter().map(String::as_str).collect();
    let Some(shutdown_at) = lines.iter().position(|l| is_shutdown_for_pod(l, pod)) else {
        return Verdict::NotChecked(format!(
            "the node never logged the bridge shutting down for pod {pod}"
        ));
    };
    let count = |ls: &[&str]| {
        ls.iter()
            .filter(|l| command_for_pod(l, pod).is_some())
            .count()
    };
    let (before, after) = (
        count(&lines[..shutdown_at]),
        count(&lines[shutdown_at + 1..]),
    );
    if before < min_before {
        return Verdict::NotChecked(format!(
            "only {before} commands logged before shutdown (need {min_before}): the guest \
             was not mid-stream, or the node is not logging workload_api_vsock at debug"
        ));
    }
    if after <= IN_FLIGHT_ALLOWANCE {
        Verdict::Held { before, after }
    } else {
        Verdict::Violated { before, after }
    }
}

fn log_len(log: &Path) -> Result<u64> {
    Ok(std::fs::metadata(log)
        .with_context(|| format!("reading {}", log.display()))?
        .len())
}

/// The log written since `offset` — this run's lines, not an earlier run's.
fn log_since(log: &Path, offset: u64) -> Result<String> {
    let bytes = std::fs::read(log).with_context(|| format!("reading {}", log.display()))?;
    let from = usize::try_from(offset)
        .unwrap_or(usize::MAX)
        .min(bytes.len());
    Ok(String::from_utf8_lossy(&bytes[from..]).into_owned())
}

/// Commands the node has logged serving `pod` since `offset`.
fn served_since(log: &Path, offset: u64, pod: &str) -> Result<usize> {
    Ok(log_since(log, offset)?
        .lines()
        .map(message)
        .filter(|l| command_for_pod(l, pod).is_some())
        .count())
}

fn one_run(node: &Node, a: &Args, spec: &Value) -> Result<(String, Verdict)> {
    if let Some(pair) = &a.fresh_scratch {
        let (scratch, template) = pair
            .split_once('=')
            .context("--fresh-scratch takes SCRATCH=TEMPLATE")?;
        std::fs::copy(template, scratch)
            .with_context(|| format!("restoring {scratch} from {template}"))?;
    }
    let offset = log_len(&a.node_log)?;
    let id = node.create_pod(&serde_json::to_string(spec)?)?;

    let deadline = Instant::now() + Duration::from_secs(a.timeout_secs);
    let mut served = 0;
    while served < a.min_before {
        if Instant::now() > deadline {
            node.cancel_pod(&id)?;
            return Ok((
                id,
                Verdict::NotChecked(format!(
                    "the guest was served only {served} commands in {}s",
                    a.timeout_secs
                )),
            ));
        }
        std::thread::sleep(Duration::from_millis(100));
        served = served_since(&a.node_log, offset, &id)?;
    }

    node.cancel_pod(&id)?;
    // `cancel` returns after teardown, but the log is written by another thread:
    // give it a moment to land before reading.
    std::thread::sleep(Duration::from_secs(2));
    let v = verdict(&log_since(&a.node_log, offset)?, &id, a.min_before);
    Ok((id, v))
}

pub fn run(a: Args) -> Result<i32> {
    if a.runs == 0 {
        bail!("--runs must be at least 1");
    }
    let node = Node::connect(&a.url, &a.tls)?;
    let raw = std::fs::read_to_string(&a.spec)
        .with_context(|| format!("reading {}", a.spec.display()))?;
    let spec: Value =
        serde_yaml::from_str(&raw).with_context(|| format!("parsing {}", a.spec.display()))?;

    let mut runs = Vec::new();
    let mut exit = 0;
    for i in 0..a.runs {
        let (id, v) = match one_run(&node, &a, &spec) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("run {i}: could not look: {e:#}");
                return Ok(2);
            }
        };
        match &v {
            Verdict::Held { before, after } => println!(
                "run {i}: pod {id}: held — {before} commands served before the bridge began \
                 shutting down, {after} after (allowance {IN_FLIGHT_ALLOWANCE})"
            ),
            Verdict::Violated { before, after } => {
                println!(
                    "run {i}: pod {id}: VIOLATED — {before} commands served before the bridge \
                     began shutting down, {after} after (allowance {IN_FLIGHT_ALLOWANCE})"
                );
                exit = 1;
            }
            Verdict::NotChecked(why) => {
                println!("run {i}: pod {id}: NOT CHECKED — {why}");
                if exit == 0 {
                    exit = 2;
                }
            }
        }
        runs.push(serde_json::json!({"pod_id": id, "verdict": v}));
    }
    if let Some(out) = &a.out {
        let report = serde_json::json!({"runs": runs, "exit": exit});
        std::fs::write(out, serde_json::to_string_pretty(&report)?)
            .with_context(|| format!("writing {}", out.display()))?;
    }
    Ok(exit)
}

#[cfg(test)]
mod tests {
    use super::*;

    const POD: &str = "0f8e2c1a-1111-4222-8333-944455556666";
    const OTHER: &str = "aaaaaaaa-1111-4222-8333-944455556666";

    fn served(pod: &str) -> String {
        format!(
            "2026-09-16T20:00:00Z DEBUG nucleus_node::workload_api_vsock: workload API FETCH_SVID for pod {pod}"
        )
    }
    fn shutdown(pod: &str) -> String {
        format!(
            "2026-09-16T20:00:01Z  INFO nucleus_node::workload_api_vsock: workload API vsock bridge shutting down for pod {pod}"
        )
    }
    fn log(parts: &[String]) -> String {
        parts.join("\n")
    }

    fn json_line(level: &str, msg: &str) -> String {
        serde_json::json!({"timestamp": "2026-09-16T19:18:37Z", "level": level,
            "fields": {"message": msg}, "target": "nucleus_node::workload_api_vsock"})
        .to_string()
    }

    /// A run reads only what the node wrote after it started: an earlier run's
    /// commands for another pod, or its shutdown line, are not this run's.
    #[test]
    fn a_run_reads_only_the_log_written_since_it_started() {
        let dir = std::env::temp_dir().join(format!("teardown-barrier-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let log = dir.join("node.log");
        let earlier: Vec<String> = (0..50)
            .map(|_| json_line("DEBUG", &format!("workload API FETCH_SVID for pod {POD}")))
            .collect();
        std::fs::write(&log, earlier.join("\n") + "\n").expect("write");
        let offset = log_len(&log).expect("len");
        assert_eq!(served_since(&log, offset, POD).expect("read"), 0);

        let mut now: Vec<String> = (0..7)
            .map(|_| json_line("DEBUG", &format!("workload API FETCH_SVID for pod {POD}")))
            .collect();
        now.push(json_line(
            "INFO",
            &format!("workload API vsock bridge shutting down for pod {POD}"),
        ));
        now.push(json_line(
            "DEBUG",
            &format!("workload API FETCH_SVID for pod {POD}"),
        ));
        let mut all = std::fs::read_to_string(&log).expect("read");
        all.push_str(&(now.join("\n") + "\n"));
        std::fs::write(&log, all).expect("append");

        assert_eq!(served_since(&log, offset, POD).expect("read"), 8);
        assert_eq!(
            verdict(&log_since(&log, offset).expect("read"), POD, 5),
            Verdict::Held {
                before: 7,
                after: 1
            }
        );
        // An offset past the end (a rotated log) reads nothing rather than panicking.
        assert_eq!(served_since(&log, u64::MAX, POD).expect("read"), 0);
        assert!(log_len(&dir.join("missing.log")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_nodes_json_log_is_read_by_its_message() {
        let line = serde_json::json!({
            "timestamp": "2026-09-16T17:55:48Z",
            "level": "DEBUG",
            "fields": {"message": format!("workload API FETCH_SVID for pod {POD}")},
            "target": "nucleus_node::workload_api_vsock",
        })
        .to_string();
        assert_eq!(command_for_pod(&message(&line), POD), Some("FETCH_SVID"));
        // The raw line is not the message: matching it directly finds nothing.
        assert_eq!(command_for_pod(&line, POD), None);
    }

    #[test]
    fn only_command_lines_for_this_pod_count() {
        assert_eq!(command_for_pod(&served(POD), POD), Some("FETCH_SVID"));
        assert_eq!(command_for_pod(&served(OTHER), POD), None);
        assert_eq!(command_for_pod(&shutdown(POD), POD), None);
        let rejected = format!("workload API rejected command for pod {POD}: unknown");
        assert_eq!(command_for_pod(&rejected, POD), None);
        // A pod id that is a prefix of another must not match it.
        assert_eq!(command_for_pod(&served(&format!("{POD}0")), POD), None);
    }

    #[test]
    fn served_during_teardown_is_violated() {
        let mut parts: Vec<String> = (0..300).map(|_| served(POD)).collect();
        parts.push(shutdown(POD));
        parts.extend((0..40).map(|_| served(POD)));
        assert_eq!(
            verdict(&log(&parts), POD, 200),
            Verdict::Violated {
                before: 300,
                after: 40
            }
        );
    }

    #[test]
    fn a_frame_in_flight_is_within_the_allowance() {
        let mut parts: Vec<String> = (0..300).map(|_| served(POD)).collect();
        parts.push(shutdown(POD));
        parts.push(served(POD));
        // Another pod's commands after the line are not this pod's.
        parts.extend((0..40).map(|_| served(OTHER)));
        assert_eq!(
            verdict(&log(&parts), POD, 200),
            Verdict::Held {
                before: 300,
                after: 1
            }
        );
    }

    #[test]
    fn no_shutdown_line_or_no_stream_is_not_checked() {
        let parts: Vec<String> = (0..300).map(|_| served(POD)).collect();
        assert!(matches!(
            verdict(&log(&parts), POD, 200),
            Verdict::NotChecked(_)
        ));
        let parts = vec![served(POD), shutdown(POD)];
        assert!(matches!(
            verdict(&log(&parts), POD, 200),
            Verdict::NotChecked(_)
        ));
    }
}
