//! `nucleus-perf guest-transcript` — A6 and A7 of the command walk, on a live
//! node (`docs/design/command-walk.md`).
//!
//! **A6, guest operations are invisible to host observations.** Boot the same
//! pod several times. Its workload is `nucleus-adversary-probe transcript`,
//! which sends a different random sequence of workload-API commands each run
//! (drawn inside the guest, so no spec field differs). Every host conclusion
//! about the pod, less the fields that are per-launch by construction, must be
//! byte-identical across the runs.
//!
//! **A7, a shipped receipt is data, never authority.** The transcripts include
//! `SHIP_RECEIPT` with garbage, truncated, forged-signature and oversized
//! bodies. They must change no host conclusion (so they are inside A6's
//! comparison), and the host's receipt verifier must refuse them by name.
//!
//! # What counts as a host conclusion
//!
//! The node-signed execution receipt's claim (exit code, stdout/stderr hashes,
//! program digest, backend, uid isolation, environment inputs, artifacts) and
//! the node-signed pod receipt, when the node produces one. Per-launch by
//! construction, and so removed before comparing: the pod id, `launch_hash`,
//! `environment_complete_sha256` (it covers the per-attempt mediator URL and
//! authentication), and the pod receipt's `timestamp_unix`, `v1_content_hash`
//! (it hashes the pod id), and signature fields. Each is named in [`PER_LAUNCH`].
//!
//! # Non-vacuity, measured on the host
//!
//! Identical conclusions across runs prove nothing if every run said the same
//! thing. The guest does not report what it sent (its output is hashed into
//! the claim); the host counts it: the node's own per-command log lines for the
//! pod, and the lines collected from `SHIP_RECEIPT`. The count is a lower bound
//! — `PING` and a frame refused before parsing are not logged — so the walk
//! requires the counts to DIFFER across runs, not to match the transcript.
//!
//! # What live runs found (nucleus-kvm, 2026-09-16)
//!
//! - **The pod receipt was unreachable for a Firecracker pod** — the microVM
//!   outlives its workload, the supervisor wrote the exit report only when it
//!   stopped serving, and cancel removed the jail the report was read from — so
//!   `GET /v1/pods/{id}/receipt` was 404 on every run. A6 over the pod receipt
//!   was reported NOT CHECKED, never as agreement. Fixed in #2925; with it, every
//!   run produces a signed pod receipt and A6 holds over it.
//! - **A workload could forge the report the node signs.** The scratch root is
//!   the workload's uid. A forgery written before the workload exits tests
//!   nothing — the supervisor's report replaces it — so `--forge-spec` runs a
//!   workload that leaves a detached process rewriting the report every 100 ms
//!   after the supervisor has written. Without #2925 the node's signed receipt
//!   repeats the forgery (verdict 1); with it the node refuses the report by
//!   name, which this harness reports as held.
//! - Some pod-receipt fields differ on every run by construction, not by anything
//!   the guest said; they are in [`PER_LAUNCH`], each with its reason.
//!
//! # Exit status
//!
//! `0` both laws held on a non-vacuous run; `1` a law was violated; `2` could
//! not look (a pod did not finish, a receipt could not be fetched, or the
//! transcripts did not measurably differ). The repository's `ci-spec` contract.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde_json::Value;

/// Fields per-launch by construction, as JSON-pointer suffixes, removed before
/// comparing. Everything else a conclusion carries must match across runs.
const PER_LAUNCH: &[&str] = &[
    // Execution claim.
    "/pod_id",
    "/launch_hash",
    "/environment_complete_sha256",
    // Pod receipt.
    "/timestamp_unix",
    // Hash-chained audit entries carry their own timestamps and a per-pod key.
    "/audit_tail_hash",
    // A hash of the spec as ADMITTED, whose policy is the issued certificate
    // lattice with a fresh id and validity window each launch.
    "/manifest_hash",
    "/v1_content_hash",
    "/signature",
    "/signer_pubkey",
];

#[derive(clap::Parser)]
pub struct Args {
    /// Node base URL (mTLS).
    #[arg(long, default_value = "https://127.0.0.1:8080")]
    pub url: String,
    /// Client certificate PEM (a SPIFFE client identity the node trusts).
    #[arg(long)]
    pub tls_cert: PathBuf,
    /// Client private key PEM.
    #[arg(long)]
    pub tls_key: PathBuf,
    /// The node's CA bundle PEM.
    #[arg(long)]
    pub trust_bundle: PathBuf,
    /// Pod spec (YAML or JSON) whose workload is `nucleus-adversary-probe transcript`.
    #[arg(long)]
    pub spec: PathBuf,
    /// Runs of the same spec. At least 3.
    #[arg(long, default_value = "6")]
    pub runs: usize,
    /// The node's `--state-dir`, where each pod's collected receipts live.
    #[arg(long)]
    pub state_dir: PathBuf,
    /// The node's log, written at debug level for `workload_api_vsock`.
    #[arg(long)]
    pub node_log: PathBuf,
    /// `nucleus-audit` binary, to verify each pod's collected receipts (A7).
    #[arg(long, default_value = "nucleus-audit")]
    pub audit_bin: String,
    /// A second spec whose workload adds `--forge-exit-report`. Measured and
    /// reported separately: a file is not part of A6's transcript.
    #[arg(long)]
    pub forge_spec: Option<PathBuf>,
    /// Restore the spec's scratch image from this template before every run, as
    /// `SCRATCH=TEMPLATE`. Without a jailer the node uses only a scratch disk the
    /// spec names, and one image shared across runs would carry one run's
    /// workspace (and any forged exit report) into the next — a difference the
    /// walk would then blame on the transcript. A copy, not a fresh `mkfs`: the
    /// execution receipt requires the scratch digest pinned, and the spawn path
    /// checks it against the placed bytes, so every run must place the same ones.
    #[arg(long, value_name = "SCRATCH=TEMPLATE")]
    pub fresh_scratch: Option<String>,
    /// Accept a run in which no pod receipt was produced. Without it, a pod
    /// receipt missing on every run is "could not look" (exit 2): two absent
    /// receipts are not two equal ones.
    #[arg(long)]
    pub pod_receipt_optional: bool,
    /// Seconds to wait for each pod to exit.
    #[arg(long, default_value = "300")]
    pub timeout_secs: u64,
    /// Write the report here as JSON.
    #[arg(long)]
    pub out: Option<PathBuf>,
}

/// What the host concluded about one run, and what it saw the guest send.
#[derive(Debug, serde::Serialize)]
struct Run {
    pod_id: String,
    exit_code: Option<i32>,
    /// Per-launch fields removed.
    claim: Option<Value>,
    pod_receipt: Result<Value, String>,
    guest_commands_logged: usize,
    receipts_shipped: usize,
    audit: Option<AuditOutcome>,
}

#[derive(Debug, serde::Serialize)]
struct AuditOutcome {
    exit_code: Option<i32>,
    /// The verifier's own words, for the report.
    output: String,
}

pub fn run(a: Args) -> Result<i32> {
    if a.runs < 3 {
        bail!("--runs must be at least 3: two runs agreeing is too easy to be luck");
    }
    let client = client(&a)?;
    let spec = read_spec(&a.spec)?;

    let mut runs = Vec::new();
    for i in 0..a.runs {
        let r = one_run(&client, &a, &spec).with_context(|| format!("run {i}"));
        match r {
            Ok(r) => {
                println!(
                    "run {i}: pod {} exit={:?} logged={} shipped={}",
                    r.pod_id, r.exit_code, r.guest_commands_logged, r.receipts_shipped
                );
                runs.push(r);
            }
            Err(e) => {
                eprintln!("could not look: {e:#}");
                return Ok(2);
            }
        }
    }

    let (mut verdict, mut report, lines) = judge(&runs, a.pod_receipt_optional);
    for line in &lines {
        println!("{line}");
    }

    if let Some(forge) = &a.forge_spec {
        let r = one_run(&client, &a, &read_spec(forge)?).context("forge run")?;
        let (outcome, violated) = forge_outcome(&r.pod_receipt);
        if violated {
            verdict = 1;
        }
        println!("EXIT-REPORT FORGERY: {outcome}");
        report.insert("forge_run", serde_json::to_value(&r)?);
        report.insert("forge_outcome", serde_json::json!(outcome));
    }

    report.insert("runs", serde_json::to_value(&runs)?);
    report.insert("verdict", serde_json::json!(verdict));
    if let Some(out) = &a.out {
        std::fs::write(out, serde_json::to_string_pretty(&report)?)
            .with_context(|| format!("writing {}", out.display()))?;
    }
    Ok(verdict)
}

fn client(a: &Args) -> Result<reqwest::blocking::Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut identity =
        std::fs::read(&a.tls_cert).with_context(|| format!("reading {}", a.tls_cert.display()))?;
    identity.push(b'\n');
    identity.extend(
        std::fs::read(&a.tls_key).with_context(|| format!("reading {}", a.tls_key.display()))?,
    );
    let roots = reqwest::Certificate::from_pem_bundle(
        &std::fs::read(&a.trust_bundle)
            .with_context(|| format!("reading {}", a.trust_bundle.display()))?,
    )?;
    // Same shape as `nucleus node`'s client: the chain is verified against the
    // node's own CA and nothing else; only hostname matching is skipped, because
    // the node's certificate names a SPIFFE URI, never a host.
    Ok(reqwest::blocking::Client::builder()
        .identity(reqwest::Identity::from_pem(&identity)?)
        .tls_certs_only(roots)
        .danger_accept_invalid_hostnames(true)
        .timeout(Duration::from_secs(60))
        .build()?)
}

/// What the runs say: the verdict before any forge run (`0`/`1`/`2`), the report's
/// fields, and the lines to print. Separate from `run` so every branch of the
/// verdict is exercised without a node.
fn judge(
    runs: &[Run],
    pod_receipt_optional: bool,
) -> (i32, BTreeMap<&'static str, Value>, Vec<String>) {
    let mut report = BTreeMap::<&'static str, Value>::new();
    let mut lines = Vec::new();
    let mut verdict = 0;

    // Non-vacuity first.
    let counts: BTreeSet<usize> = runs
        .iter()
        .map(|r| r.guest_commands_logged + r.receipts_shipped)
        .collect();
    let shipped_any = runs.iter().any(|r| r.receipts_shipped > 0);
    let spread = counts.iter().max().unwrap_or(&0) - counts.iter().min().unwrap_or(&0);
    let vacuous = counts.len() < 2 || spread < 2;
    report.insert("guest_command_counts", serde_json::json!(counts));
    if vacuous {
        lines.push(format!(
            "NON-VACUITY: transcripts did not measurably differ (counts {counts:?})"
        ));
        verdict = verdict.max(2);
    }

    // A two-sided absence is not agreement.
    if runs.iter().all(|r| r.pod_receipt.is_err()) {
        let why = runs
            .first()
            .and_then(|r| r.pod_receipt.as_ref().err())
            .cloned()
            .unwrap_or_default();
        lines.push(format!(
            "A6 pod receipt: NOT CHECKED, produced on no run ({why})"
        ));
        report.insert("pod_receipt_checked", serde_json::json!(false));
        if !pod_receipt_optional {
            verdict = verdict.max(2);
        }
    }

    // A6: every conclusion equal.
    let a6 = compare(runs);
    report.insert("a6_differences", serde_json::json!(a6));
    if a6.is_empty() {
        lines.push(format!(
            "A6: host conclusions identical across {} runs",
            runs.len()
        ));
    } else {
        lines.push(format!("A6 VIOLATED: {a6:#?}"));
        verdict = 1;
    }

    // A7: shipped bodies are refused by the verifier, and never accepted.
    if !shipped_any {
        lines.push("A7: no run shipped a receipt; not checked".to_string());
        verdict = verdict.max(2);
    }
    let accepted: Vec<&str> = runs
        .iter()
        .filter(|r| r.receipts_shipped > 0)
        .filter(|r| r.audit.as_ref().is_some_and(|o| o.exit_code == Some(0)))
        .map(|r| r.pod_id.as_str())
        .collect();
    report.insert(
        "a7_verifier_accepted_guest_bodies",
        serde_json::json!(accepted),
    );
    if shipped_any && accepted.is_empty() {
        lines.push(
            "A7: every log carrying guest-shipped bodies was refused by the verifier".to_string(),
        );
    } else if !accepted.is_empty() {
        lines.push(format!(
            "A7 VIOLATED: the verifier accepted guest-shipped bodies for {accepted:?}"
        ));
        verdict = 1;
    }
    (verdict, report, lines)
}

/// The forge run's outcome, and whether it is a violation. Three outcomes, not
/// two: no receipt at all is neither a repeated forgery nor a refused one.
fn forge_outcome(pod_receipt: &Result<Value, String>) -> (String, bool) {
    match pod_receipt {
        // Refused by name: the node would not sign a report that is not the
        // supervisor's. That is the law holding, not a failure to look.
        Err(e) if e.contains("not the supervisor") => (
            format!("held: the node refused the forged report ({e})"),
            false,
        ),
        Err(e) => (
            format!("NOT CHECKED: no pod receipt was produced ({e})"),
            false,
        ),
        Ok(v) if v.get("workspace_hash").and_then(Value::as_str) == Some("forged-by-the-guest") => {
            (
                "VIOLATED: the node's signed pod receipt repeats the guest-written workspace_hash"
                    .to_string(),
                true,
            )
        }
        Ok(_) => (
            "held: the node's signed pod receipt does not repeat the forgery".to_string(),
            false,
        ),
    }
}

fn read_spec(path: &Path) -> Result<Value> {
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_yaml::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

fn get_json(client: &reqwest::blocking::Client, url: &str) -> Result<Value, String> {
    let resp = client.get(url).send().map_err(|e| format!("{url}: {e}"))?;
    let status = resp.status();
    let text = resp.text().map_err(|e| format!("{url}: body: {e}"))?;
    if !status.is_success() {
        return Err(format!("{url}: HTTP {status}: {}", text.trim()));
    }
    serde_json::from_str(&text).map_err(|e| format!("{url}: not JSON: {e}"))
}

fn one_run(client: &reqwest::blocking::Client, a: &Args, spec: &Value) -> Result<Run> {
    if let Some(pair) = &a.fresh_scratch {
        let (scratch, template) = pair
            .split_once('=')
            .context("--fresh-scratch takes SCRATCH=TEMPLATE")?;
        std::fs::copy(template, scratch)
            .with_context(|| format!("restoring {scratch} from {template}"))?;
    }
    let resp = client
        .post(format!("{}/v1/pods", a.url))
        .json(spec)
        .send()
        .context("create pod")?;
    let status = resp.status();
    let text = resp.text().unwrap_or_default();
    if !status.is_success() {
        bail!("create pod: HTTP {status}: {}", text.trim());
    }
    let created: Value = serde_json::from_str(&text).context("create pod: response")?;
    let id = created
        .get("id")
        .and_then(Value::as_str)
        .context("create pod: no id")?
        .to_string();

    // The microVM outlives its workload — the supervisor stays up to serve the
    // result — so "done" is the WORKLOAD's exit, read from the supervisor's own
    // observation, and the pod is then cancelled for the receipt that needs it.
    wait_for_workload(client, a, &id)?;
    let claim = get_json(client, &format!("{}/v1/pods/{id}/execution-receipt", a.url))
        .map_err(anyhow::Error::msg)
        .context("execution receipt")?;
    let claim = find_claim(&claim).context("execution receipt carries no claim")?;
    let exit_code = claim
        .get("exit_code")
        .and_then(Value::as_i64)
        .map(|c| c as i32);

    let cancel = client
        .post(format!("{}/v1/pods/{id}/cancel", a.url))
        .send()
        .context("cancel pod")?;
    if !cancel.status().is_success() {
        bail!("cancel pod {id}: HTTP {}", cancel.status());
    }
    wait_for_exit(client, a, &id)?;
    let pod_receipt = get_json(client, &format!("{}/v1/pods/{id}/receipt", a.url));
    finish(a, id, exit_code, claim, pod_receipt)
}

fn finish(
    a: &Args,
    id: String,
    exit_code: Option<i32>,
    claim: Value,
    pod_receipt: Result<Value, String>,
) -> Result<Run> {
    let pod_dir = a.state_dir.join("pods").join(&id);
    let collected = pod_dir.join("collected-receipts.jsonl");
    let receipts_shipped = std::fs::read_to_string(&collected)
        .map(|s| s.lines().filter(|l| !l.trim().is_empty()).count())
        .unwrap_or(0);
    let audit = (receipts_shipped > 0).then(|| audit(&a.audit_bin, &collected));
    let guest_commands_logged = std::fs::read_to_string(&a.node_log)
        .with_context(|| format!("reading {}", a.node_log.display()))?
        .lines()
        .filter(|l| l.contains("workload API") && l.contains(&id))
        .count();

    Ok(Run {
        pod_id: id,
        exit_code,
        claim: Some(strip(claim)),
        pod_receipt: pod_receipt.map(strip),
        guest_commands_logged,
        receipts_shipped,
        audit,
    })
}

/// Wait until the supervisor reports the workload exited. `Unavailable` and
/// `NotConfigured` are not waited out: they say the walk cannot look.
fn wait_for_workload(client: &reqwest::blocking::Client, a: &Args, id: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(a.timeout_secs);
    let mut last = String::new();
    while Instant::now() < deadline {
        match get_json(client, &format!("{}/v1/pods/{id}/workload-result", a.url)) {
            Ok(v) if find_key(&v, "stdout_sha256") => return Ok(()),
            Ok(v) => {
                let s = v.to_string();
                if s.contains("not_configured") || s.contains("unavailable") {
                    bail!("pod {id}: the supervisor cannot report a result: {s}");
                }
                last = s;
            }
            // The supervisor comes up a moment after the pod does.
            Err(e) => last = e,
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    bail!(
        "pod {id}: workload did not finish within {}s (last: {last})",
        a.timeout_secs
    )
}

fn find_key(v: &Value, key: &str) -> bool {
    match v {
        Value::Object(o) => o.contains_key(key) || o.values().any(|x| find_key(x, key)),
        Value::Array(a) => a.iter().any(|x| find_key(x, key)),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

fn wait_for_exit(client: &reqwest::blocking::Client, a: &Args, id: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(a.timeout_secs);
    while Instant::now() < deadline {
        let pods = get_json(client, &format!("{}/v1/pods", a.url)).map_err(anyhow::Error::msg)?;
        let state = pods
            .as_array()
            .and_then(|ps| {
                ps.iter()
                    .find(|p| p.get("id").and_then(Value::as_str) == Some(id))
            })
            .and_then(|p| p.get("state"))
            .cloned();
        if state.as_ref().and_then(|s| s.get("exited")).is_some() {
            return Ok(());
        }
        if let Some(err) = state.as_ref().and_then(|s| s.get("error")) {
            bail!("pod {id} errored: {err}");
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    bail!("pod {id} did not exit within {}s", a.timeout_secs)
}

/// The claim inside a signed execution receipt: the object that names a
/// `program_digest`, wherever the projection encoding puts it.
fn find_claim(v: &Value) -> Option<Value> {
    match v {
        Value::Object(o) if o.contains_key("program_digest") => Some(v.clone()),
        Value::Object(o) => o.values().find_map(find_claim),
        Value::Array(a) => a.iter().find_map(find_claim),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => None,
    }
}

/// Remove the per-launch fields, at any depth.
fn strip(mut v: Value) -> Value {
    fn go(v: &mut Value, path: &str) {
        match v {
            Value::Object(o) => {
                o.retain(|k, _| {
                    let p = format!("{path}/{k}");
                    !PER_LAUNCH.iter().any(|s| p.ends_with(s))
                });
                for (k, x) in o.iter_mut() {
                    go(x, &format!("{path}/{k}"));
                }
            }
            Value::Array(a) => {
                for (i, x) in a.iter_mut().enumerate() {
                    go(x, &format!("{path}/{i}"));
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }
    go(&mut v, "");
    v
}

fn audit(bin: &str, log: &Path) -> AuditOutcome {
    match std::process::Command::new(bin)
        .args(["verify-mediation-receipts", "--log"])
        .arg(log)
        .output()
    {
        Ok(out) => AuditOutcome {
            exit_code: out.status.code(),
            output: format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            )
            .trim()
            .chars()
            .take(600)
            .collect(),
        },
        Err(e) => AuditOutcome {
            exit_code: None,
            output: format!("could not run {bin}: {e}"),
        },
    }
}

/// Every conclusion that differs between runs: `(what, run index, value)`.
fn compare(runs: &[Run]) -> Vec<String> {
    let Some(first) = runs.first() else {
        return Vec::new();
    };
    let mut diffs = Vec::new();
    for (i, r) in runs.iter().enumerate().skip(1) {
        if r.exit_code != first.exit_code {
            diffs.push(format!(
                "run {i}: exit {:?} vs {:?}",
                r.exit_code, first.exit_code
            ));
        }
        if r.claim != first.claim {
            diffs.push(format!(
                "run {i}: execution claim differs: {}",
                pointer_diff(first.claim.as_ref(), r.claim.as_ref())
            ));
        }
        let receipt = |x: &Result<Value, String>| x.as_ref().ok().cloned();
        match (&first.pod_receipt, &r.pod_receipt) {
            (Ok(_), Ok(_)) if receipt(&first.pod_receipt) != receipt(&r.pod_receipt) => {
                diffs.push(format!(
                    "run {i}: pod receipt differs: {}",
                    pointer_diff(
                        receipt(&first.pod_receipt).as_ref(),
                        receipt(&r.pod_receipt).as_ref()
                    )
                ));
            }
            // Produced on one run and not another is itself a difference in
            // what the host concluded.
            (Ok(_), Err(e)) | (Err(e), Ok(_)) => {
                diffs.push(format!(
                    "run {i}: pod receipt produced on one run only: {e}"
                ));
            }
            (Ok(_), Ok(_)) | (Err(_), Err(_)) => {}
        }
    }
    diffs
}

fn pointer_diff(a: Option<&Value>, b: Option<&Value>) -> String {
    fn leaves(v: &Value, p: &str, out: &mut BTreeMap<String, String>) {
        match v {
            Value::Object(o) => o
                .iter()
                .for_each(|(k, x)| leaves(x, &format!("{p}/{k}"), out)),
            Value::Array(a) => a
                .iter()
                .enumerate()
                .for_each(|(i, x)| leaves(x, &format!("{p}/{i}"), out)),
            other => {
                out.insert(p.to_string(), other.to_string());
            }
        }
    }
    let (mut la, mut lb) = (BTreeMap::new(), BTreeMap::new());
    if let Some(a) = a {
        leaves(a, "", &mut la);
    }
    if let Some(b) = b {
        leaves(b, "", &mut lb);
    }
    let keys: BTreeSet<&String> = la.keys().chain(lb.keys()).collect();
    keys.into_iter()
        .filter(|k| la.get(*k) != lb.get(*k))
        .map(|k| format!("{k}: {:?} -> {:?}", la.get(k), lb.get(k)))
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_launch_fields_are_removed_at_any_depth_and_nothing_else_is() {
        let v = serde_json::json!({
            "projections": [{"ci": {"pod_id": "a", "launch_hash": "b", "program_digest": "p", "exit_code": 0}}],
            "timestamp_unix": 5,
            "workspace_hash": "w"
        });
        let s = strip(v);
        assert_eq!(
            s,
            serde_json::json!({
                "projections": [{"ci": {"program_digest": "p", "exit_code": 0}}],
                "workspace_hash": "w"
            })
        );
    }

    #[test]
    fn the_claim_is_found_inside_the_receipt_encoding() {
        let v =
            serde_json::json!({"session": {}, "projections": [{"Ci": {"program_digest": "p"}}]});
        assert_eq!(
            find_claim(&v),
            Some(serde_json::json!({"program_digest": "p"}))
        );
        assert_eq!(find_claim(&serde_json::json!({"x": 1})), None);
    }

    /// Control for the comparison: two runs that differ in a non-per-launch
    /// field ARE reported, so an empty difference list means something.
    #[test]
    fn a_differing_conclusion_is_reported() {
        let run = |stdout: &str| Run {
            pod_id: "x".into(),
            exit_code: Some(0),
            claim: Some(serde_json::json!({"stdout_sha256": stdout})),
            pod_receipt: Err("none".into()),
            guest_commands_logged: 0,
            receipts_shipped: 0,
            audit: None,
        };
        assert!(compare(&[run("a"), run("a"), run("a")]).is_empty());
        let d = compare(&[run("a"), run("a"), run("b")]);
        assert_eq!(d.len(), 1, "{d:?}");
        assert!(d[0].contains("/stdout_sha256"), "{d:?}");
    }

    fn run_with(id: &str, logged: usize, shipped: usize, audit_exit: Option<i32>) -> Run {
        Run {
            pod_id: id.into(),
            exit_code: Some(0),
            claim: Some(serde_json::json!({"stdout_sha256": "same"})),
            pod_receipt: Ok(serde_json::json!({"workspace_hash": "w"})),
            guest_commands_logged: logged,
            receipts_shipped: shipped,
            audit: (shipped > 0).then(|| AuditOutcome {
                exit_code: audit_exit,
                output: String::new(),
            }),
        }
    }

    /// A fresh directory under the system temp dir, removed by the caller.
    fn scratch_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let d = std::env::temp_dir().join(format!(
            "guest-transcript-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&d).expect("scratch dir");
        d
    }

    #[test]
    fn differing_transcripts_that_were_refused_hold() {
        let runs = [
            run_with("a", 3, 1, Some(1)),
            run_with("b", 9, 2, Some(1)),
            run_with("c", 0, 0, None),
        ];
        let (verdict, report, lines) = judge(&runs, false);
        assert_eq!(verdict, 0, "{lines:?}");
        assert_eq!(report["a6_differences"], serde_json::json!([]));
        assert!(
            lines.iter().any(|l| l.starts_with("A7: every log")),
            "{lines:?}"
        );
    }

    #[test]
    fn identical_transcripts_are_could_not_look() {
        let runs = [run_with("a", 4, 1, Some(1)), run_with("b", 4, 1, Some(1))];
        let (verdict, _, lines) = judge(&runs, false);
        assert_eq!(verdict, 2);
        assert!(
            lines.iter().any(|l| l.starts_with("NON-VACUITY")),
            "{lines:?}"
        );
    }

    #[test]
    fn nothing_shipped_is_could_not_look_for_a7() {
        let runs = [run_with("a", 1, 0, None), run_with("b", 9, 0, None)];
        let (verdict, report, lines) = judge(&runs, false);
        assert_eq!(verdict, 2);
        assert!(
            lines.iter().any(|l| l.contains("no run shipped")),
            "{lines:?}"
        );
        assert_eq!(
            report["a7_verifier_accepted_guest_bodies"],
            serde_json::json!([])
        );
    }

    #[test]
    fn an_accepted_guest_body_is_a_violation() {
        let runs = [run_with("a", 1, 1, Some(0)), run_with("b", 9, 1, Some(1))];
        let (verdict, report, lines) = judge(&runs, false);
        assert_eq!(verdict, 1, "{lines:?}");
        assert_eq!(
            report["a7_verifier_accepted_guest_bodies"],
            serde_json::json!(["a"])
        );
    }

    #[test]
    fn a_receipt_absent_on_every_run_is_not_agreement_unless_optional() {
        let mut runs = [run_with("a", 1, 1, Some(1)), run_with("b", 9, 1, Some(1))];
        for r in &mut runs {
            r.pod_receipt = Err("404".into());
        }
        let (strict, report, _) = judge(&runs, false);
        assert_eq!(strict, 2);
        assert_eq!(report["pod_receipt_checked"], serde_json::json!(false));
        let (optional, _, _) = judge(&runs, true);
        assert_eq!(optional, 0);
    }

    #[test]
    fn a_differing_conclusion_makes_the_verdict_a_violation() {
        let mut runs = [run_with("a", 1, 1, Some(1)), run_with("b", 9, 1, Some(1))];
        runs[1].exit_code = Some(3);
        let (verdict, _, lines) = judge(&runs, false);
        assert_eq!(verdict, 1);
        assert!(
            lines.iter().any(|l| l.starts_with("A6 VIOLATED")),
            "{lines:?}"
        );
        assert!(judge(&[], false).2.iter().any(|l| l.contains("0 runs")));
    }

    #[test]
    fn a_pod_receipt_on_one_run_only_or_differing_is_a_difference() {
        let base = run_with("a", 1, 0, None);
        let mut missing = run_with("b", 1, 0, None);
        missing.pod_receipt = Err("404".into());
        let d = compare(&[base, missing]);
        assert!(d[0].contains("one run only"), "{d:?}");

        let mut changed = run_with("c", 1, 0, None);
        changed.pod_receipt = Ok(serde_json::json!({"workspace_hash": "other"}));
        let d = compare(&[run_with("a", 1, 0, None), changed]);
        assert!(d[0].contains("/workspace_hash"), "{d:?}");
        assert!(compare(&[]).is_empty());
    }

    #[test]
    fn the_forge_run_has_four_outcomes() {
        let (o, v) = forge_outcome(&Err("exit report is not the supervisor's".into()));
        assert!(o.starts_with("held") && !v, "{o}");
        let (o, v) = forge_outcome(&Err("HTTP 404".into()));
        assert!(o.starts_with("NOT CHECKED") && !v, "{o}");
        let (o, v) = forge_outcome(&Ok(
            serde_json::json!({"workspace_hash": "forged-by-the-guest"}),
        ));
        assert!(o.starts_with("VIOLATED") && v, "{o}");
        let (o, v) = forge_outcome(&Ok(serde_json::json!({"workspace_hash": "real"})));
        assert!(o.starts_with("held") && !v, "{o}");
    }

    #[test]
    fn pointer_diff_names_changed_added_and_removed_leaves() {
        let a = serde_json::json!({"x": 1, "list": [1, 2], "gone": true});
        let b = serde_json::json!({"x": 2, "list": [1, 2], "new": null});
        let d = pointer_diff(Some(&a), Some(&b));
        assert!(
            d.contains("/x") && d.contains("/gone") && d.contains("/new"),
            "{d}"
        );
        assert!(!d.contains("/list"), "{d}");
        assert!(pointer_diff(None, Some(&b)).contains("/x"));
        assert!(pointer_diff(None, None).is_empty());
    }

    #[test]
    fn find_key_searches_nested_objects_and_arrays() {
        let v = serde_json::json!({"result": [{"inner": {"stdout_sha256": "h"}}]});
        assert!(find_key(&v, "stdout_sha256"));
        assert!(!find_key(&v, "stderr_sha256"));
        assert!(!find_key(
            &serde_json::json!("stdout_sha256"),
            "stdout_sha256"
        ));
    }

    #[test]
    fn a_spec_is_read_as_yaml_and_a_missing_one_is_an_error() {
        let dir = scratch_dir("spec");
        let path = dir.join("pod.yaml");
        std::fs::write(
            &path,
            "kind: Pod\nspec:\n  workload:\n    args: [transcript]\n",
        )
        .expect("write spec");
        let v = read_spec(&path).expect("parses");
        assert_eq!(v["spec"]["workload"]["args"][0], "transcript");
        assert!(read_spec(&dir.join("absent.yaml")).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `finish` counts what the HOST recorded for this pod — its collected receipts
    /// and its own log lines naming the pod — and runs the verifier only when a
    /// receipt was shipped.
    #[test]
    fn finish_counts_the_hosts_record_for_this_pod_only() {
        use clap::Parser;
        let dir = scratch_dir("finish");
        let id = "pod-1234";
        let pod_dir = dir.join("pods").join(id);
        std::fs::create_dir_all(&pod_dir).expect("pod dir");
        std::fs::write(pod_dir.join("collected-receipts.jsonl"), "{}\n\n{}\n").expect("receipts");
        let log = dir.join("node.log");
        std::fs::write(
            &log,
            format!(
                "workload API PING for pod {id}\nworkload API PING for pod other\nunrelated {id}\nworkload API POD_LIST for pod {id}\n"
            ),
        )
        .expect("log");
        let args = |bin: &str| {
            Args::try_parse_from([
                "guest-transcript",
                "--tls-cert",
                "c.pem",
                "--tls-key",
                "k.pem",
                "--trust-bundle",
                "b.pem",
                "--spec",
                "unused.yaml",
                "--state-dir",
                dir.to_str().expect("utf-8 path"),
                "--node-log",
                log.to_str().expect("utf-8 path"),
                "--audit-bin",
                bin,
            ])
            .expect("args parse")
        };

        let claim = serde_json::json!({"program_digest": "p", "pod_id": id});
        let r = finish(
            &args("true"),
            id.into(),
            Some(0),
            claim.clone(),
            Err("404".into()),
        )
        .expect("finish");
        assert_eq!(r.receipts_shipped, 2);
        assert_eq!(r.guest_commands_logged, 2);
        assert_eq!(r.claim, Some(serde_json::json!({"program_digest": "p"})));
        assert_eq!(r.audit.as_ref().and_then(|a| a.exit_code), Some(0));

        // A verifier that cannot be run is reported as such, never as a verdict.
        let r = finish(
            &args("/nonexistent/nucleus-audit"),
            id.into(),
            Some(0),
            claim.clone(),
            Ok(serde_json::json!({"timestamp_unix": 1, "workspace_hash": "w"})),
        )
        .expect("finish");
        let audit = r.audit.expect("a receipt was shipped, so the verifier ran");
        assert_eq!(audit.exit_code, None);
        assert!(audit.output.contains("could not run"), "{}", audit.output);
        assert_eq!(
            r.pod_receipt.ok(),
            Some(serde_json::json!({"workspace_hash": "w"}))
        );

        // Nothing shipped: the verifier is not run at all.
        let r = finish(
            &args("true"),
            "no-such-pod".into(),
            None,
            claim,
            Err("x".into()),
        )
        .expect("finish");
        assert_eq!((r.receipts_shipped, r.guest_commands_logged), (0, 0));
        assert!(r.audit.is_none());

        // A node log that cannot be read is an error, not zero commands.
        let missing = Args::try_parse_from([
            "guest-transcript",
            "--tls-cert",
            "c.pem",
            "--tls-key",
            "k.pem",
            "--trust-bundle",
            "b.pem",
            "--spec",
            "unused.yaml",
            "--state-dir",
            dir.to_str().expect("utf-8 path"),
            "--node-log",
            dir.join("absent.log").to_str().expect("utf-8 path"),
        ])
        .expect("args parse");
        assert!(
            finish(
                &missing,
                id.into(),
                None,
                serde_json::json!({}),
                Err("x".into())
            )
            .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
