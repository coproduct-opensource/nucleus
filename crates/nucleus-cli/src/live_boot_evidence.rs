//! The collector half of `cargo xtask live-boot-evidence`: boot a real pod on a
//! fresh, host-spec-enforcing node and write down what a stranger would be
//! handed. It VERIFIES NOTHING. The appraiser reads the directory with the
//! public verifiers only, so a check that lived here would be a check the
//! stranger cannot repeat.
//!
//! Requires Linux, KVM, root, and installed guest artifacts (`nucleus setup`).
//! Never a mock driver. Invoked by the xtask, which passes its inputs as
//! `NUCLEUS_LIVE_BOOT_*` variables on the command line it runs under `sudo`.
use anyhow::{Context, Result, bail, ensure};
use nucleus_spec::live_boot::{
    self, Collection, EvalCellRun, Files, Measured, MeasuredHow, NodeEvidence,
};
use nucleus_spec::workload_result::WorkloadResult;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use uuid::Uuid;

use crate::host_evidence_live::{self as live, node::Node};

/// Where `nucleus setup` installs the VMM; the fixture node is started with
/// these paths, so they are what the measurements are keyed by.
const FIRECRACKER: &str = "/usr/local/bin/firecracker";
const JAILER: &str = "/usr/local/bin/jailer";

/// The posture workload. Every probe runs whatever the one before it said, so
/// each prints its own verdict; the exit is zero only if all of them passed.
/// The last line writes the declared artifact.
fn workload_script(nonce: &str) -> String {
    let note = live_boot::artifact_bytes(nonce);
    let note = note.trim_end();
    format!(
        "/usr/local/bin/nucleus-workload-probe; w=$?; \
         /usr/local/bin/nucleus-workload-probe --syscall-filter; s=$?; \
         /usr/local/bin/nucleus-workload-probe --run-child; r=$?; \
         /usr/local/bin/nucleus-egress-probe; e=$?; \
         /usr/local/bin/nucleus-adversary-probe; a=$?; \
         printf '%s\\n' '{note}' > /work/{path}; \
         [ $w -eq 0 ] && [ $s -eq 0 ] && [ $r -eq 0 ] && [ $e -eq 0 ] && [ $a -eq 0 ]",
        path = live_boot::ARTIFACT_PATH,
    )
}

/// The environment the request sets. Named in full, because the receipt
/// commits to every resolved input and the expectations must name them all.
fn environment() -> std::collections::BTreeMap<String, String> {
    [
        ("HOME", "/work/.home"),
        ("PATH", "/usr/bin:/bin"),
        ("LANG", "C"),
        ("TZ", "UTC"),
    ]
    .into_iter()
    .map(|(k, v)| (k.into(), v.into()))
    .collect()
}

fn execution_spec(
    manifest: &crate::workload_verification::Manifest,
    nonce: &str,
) -> Result<serde_json::Value> {
    Ok(json!({
        "apiVersion":"nucleus/v1", "kind":"Pod",
        "metadata":{"name":"live-boot-evidence"},
        "spec":{
            "work_dir":"/work", "timeout_seconds":900,
            "policy":{"type":"profile", "name":"demo"},
            "network":{"allow":[], "deny":[]},
            "workload":{
                "command":"/bin/sh", "args":["-c", workload_script(nonce)],
                "uid":65534,
                "env":environment(),
                "artifacts":{(live_boot::ARTIFACT_NAME):live_boot::ARTIFACT_PATH},
            },
            "image":guest_image(manifest)?,
            "vsock":{"guest_cid":3,"port":5005},
            "seccomp":{"mode":"default"},
        }
    }))
}

/// The installed guest, its kernel and rootfs pinned by digest.
fn guest_image(manifest: &crate::workload_verification::Manifest) -> Result<serde_json::Value> {
    let digest = |name: &str| -> Result<String> {
        let input = manifest
            .files
            .get(name)
            .with_context(|| format!("host manifest has no {name}"))?;
        Ok(format!("sha-256:{}", input.sha256.to_ascii_lowercase()))
    };
    Ok(json!({
        "kernel_path":nucleus_spec::microvm_host::guest_kernel_path(),
        "rootfs_path":nucleus_spec::microvm_host::guest_rootfs_path(),
        "kernel_digest":digest(nucleus_spec::tier2_artifacts::GUEST_KERNEL_FILE)?,
        "rootfs_digest":digest(nucleus_spec::tier2_artifacts::GUEST_ROOTFS_FILE)?,
        "read_only":true,
    }))
}

/// The eval cell's workload: ordinary local work, and no network at all.
const EVAL_CELL_WORKLOAD: &str =
    "printf 'eval-cell\\n' > /work/eval-cell.txt && cat /work/eval-cell.txt";

/// An honest eval cell (ADR 0013, ADR 0015 E1): labelled `eval-cell`, on the
/// same pinned guest as the execution pod, with the same empty network policy,
/// a policy that grants no network capability, the default VMM seccomp filter
/// and no audit sink. It lists no destination because it sends nothing.
fn eval_cell_spec(manifest: &crate::workload_verification::Manifest) -> Result<serde_json::Value> {
    use nucleus_spec::isolation_profile::{IsolationProfile, PROFILE_LABEL};
    let mut lattice = nucleus_spec::PolicySpec::Profile {
        name: "codegen".into(),
    }
    .resolve()
    .context("the codegen profile")?;
    lattice.capabilities.web_fetch = portcullis::CapabilityLevel::Never;
    lattice.capabilities.web_search = portcullis::CapabilityLevel::Never;
    Ok(json!({
        "apiVersion":"nucleus/v1", "kind":"Pod",
        "metadata":{
            "name":"live-boot-eval-cell",
            "labels":{(PROFILE_LABEL):IsolationProfile::EvalCell.name()},
        },
        "spec":{
            "work_dir":"/work", "timeout_seconds":300,
            "policy":nucleus_spec::PolicySpec::Inline { lattice: Box::new(lattice) },
            "network":{"allow":[], "deny":[]},
            "workload":{
                "command":"/bin/sh", "args":["-c", EVAL_CELL_WORKLOAD],
                "uid":65534,
                "env":environment(),
            },
            "image":guest_image(manifest)?,
            "vsock":{"guest_cid":3,"port":5005},
            "seccomp":{"mode":"default"},
        }
    }))
}

fn millis(since: Instant) -> u64 {
    u64::try_from(since.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

/// The executable a running process was started from, as bytes that ran.
fn process_exe(pid: u32, path: &str) -> Result<Measured> {
    let link = PathBuf::from(format!("/proc/{pid}/exe"));
    let exe = std::fs::read_link(&link)
        .with_context(|| format!("reading {}", link.display()))?
        .display()
        .to_string();
    Ok(Measured {
        path: path.into(),
        sha256: sha256_file(&link)?,
        how: MeasuredHow::ProcessExe { pid, exe },
    })
}

/// The Firecracker process serving `pod`: the jailer passes the pod id as
/// `--id`, and the executable is the jail's copy of the configured binary.
fn firecracker_for(pod: Uuid) -> Result<Measured> {
    process_exe(firecracker_pid(pod)?, FIRECRACKER)
}

/// The filter table of the network namespace `pod`'s VMM runs in, with its
/// packet counters (`iptables-save -c`): the fence as the guest's traffic left
/// it (ADR 0015 E1). Taken before the pod is cancelled, because teardown
/// deletes the namespace. Read through the VMM's own `/proc/<pid>/ns/net`, so
/// it is the namespace the guest's tap is in, not one found by name.
fn fence_snapshot(pod: Uuid) -> Result<String> {
    let pid = firecracker_pid(pod)?;
    let output = std::process::Command::new("nsenter")
        .arg(format!("--net=/proc/{pid}/ns/net"))
        .args(["--", "iptables-save", "-c"])
        .output()
        .context("running iptables-save in the pod's network namespace")?;
    ensure!(
        output.status.success(),
        "iptables-save in pod {pod}'s namespace: {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).context("iptables-save printed non-UTF-8")
}

fn firecracker_pid(pod: Uuid) -> Result<u32> {
    let id = pod.to_string();
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc")?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
        let is_firecracker = args.first().is_some_and(|a| {
            Path::new(std::str::from_utf8(a).unwrap_or_default())
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("firecracker"))
        });
        if is_firecracker && args.contains(&id.as_bytes()) {
            found.push(pid);
        }
    }
    match found.as_slice() {
        [pid] => Ok(*pid),
        [] => bail!("no running firecracker process names pod {pod}"),
        many => bail!("several firecracker processes name pod {pod}: {many:?}"),
    }
}

async fn get(node: &Node, url: &str) -> Result<(u16, Vec<u8>)> {
    let response = node.client.get(url).send().await?;
    let status = response.status().as_u16();
    Ok((status, response.bytes().await?.to_vec()))
}

async fn ok(node: &Node, url: &str) -> Result<Vec<u8>> {
    let (status, bytes) = get(node, url).await?;
    ensure!(
        status == 200,
        "GET {url}: HTTP {status}: {}",
        String::from_utf8_lossy(&bytes)
    );
    Ok(bytes)
}

async fn create(node: &Node, spec: &serde_json::Value) -> Result<(live::Created, u64)> {
    let start = Instant::now();
    let created: live::Created = serde_json::from_slice(
        &live::body(
            node.client
                .post(format!("{}/v1/pods", node.url))
                .timeout(nucleus_spec::boot_budget::POD_CREATE_CLIENT_TIMEOUT)
                .json(spec)
                .send()
                .await?,
        )
        .await?,
    )?;
    Ok((created, millis(start)))
}

async fn cancel(node: &Node, pod: Uuid) -> Result<()> {
    live::body(
        node.client
            .post(format!("{}/v1/pods/{pod}/cancel", node.url))
            .send()
            .await?,
    )
    .await
    .map(drop)
}

/// Run `work` against `pod`, then cancel it whatever happened; a failed
/// cancellation is never hidden behind a failed `work`.
async fn then_cancel<T>(
    node: &Node,
    pod: Uuid,
    work: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    let result = work.await;
    match (result, cancel(node, pod).await) {
        (Ok(v), Ok(())) => Ok(v),
        (Err(e), Ok(())) => Err(e.context(format!("pod {pod} cancelled"))),
        (result, Err(e)) => bail!(
            "pod {pod} cancellation failed: {e}; collection: {:?}",
            result.err()
        ),
    }
}

/// When a workload's supervisor first answered and when it reported the exit.
struct Exit {
    ready_ms: u64,
    exit_ms: u64,
    exit_code: Option<i32>,
}

/// Poll `base`'s workload result until it reports the exit.
async fn wait_exit(node: &Node, base: &str, started: Instant) -> Result<Exit> {
    let mut ready_ms = None;
    let (exit_ms, exit_code) = tokio::time::timeout(Duration::from_secs(600), async {
        loop {
            let (status, bytes) = get(node, &format!("{base}/workload-result")).await?;
            if status == 200 {
                ready_ms.get_or_insert_with(|| millis(started));
                match serde_json::from_slice::<WorkloadResult>(&bytes)? {
                    WorkloadResult::Exited { exit_code, .. } => {
                        return Ok::<_, anyhow::Error>((millis(started), exit_code));
                    }
                    WorkloadResult::Running => {}
                    WorkloadResult::NotConfigured => bail!("the workload was not configured"),
                    WorkloadResult::Unavailable { reason } => {
                        bail!("the workload is unavailable: {reason}")
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .context("timed out waiting for the workload to exit")??;
    Ok(Exit {
        ready_ms: ready_ms.context("the supervisor never answered")?,
        exit_ms,
        exit_code,
    })
}

struct Execution {
    pod: Uuid,
    create_ms: u64,
    ready_ms: u64,
    exit_ms: u64,
    firecracker: Measured,
    node_evidence: NodeEvidence,
}

async fn execution(node: &Node, out: &Path, files: &Files, nonce: &str) -> Result<Execution> {
    let manifest =
        tokio::task::spawn_blocking(crate::workload_verification::installed_manifest).await??;
    let spec = execution_spec(&manifest, nonce)?;
    std::fs::write(out.join(&files.spec), serde_json::to_vec_pretty(&spec)?)?;
    std::fs::write(
        out.join(&files.environment_inputs),
        serde_json::to_vec_pretty(&environment())?,
    )?;
    let selection = json!({(live_boot::ARTIFACT_NAME): live_boot::ARTIFACT_PATH});
    std::fs::write(
        out.join(&files.artifact_selection),
        serde_json::to_vec_pretty(&selection)?,
    )?;
    let started = Instant::now();
    let (created, create_ms) = create(node, &spec).await?;
    let pod = created.id;
    then_cancel(node, pod, async {
        let firecracker = firecracker_for(pod)?;
        let base = format!("{}/v1/pods/{pod}", node.url);
        let admission = ok(node, &format!("{base}/workload-admission")).await?;
        std::fs::write(out.join(&files.admission), admission)?;
        let Exit {
            ready_ms, exit_ms, ..
        } = wait_exit(node, &base, started)
            .await
            .context("the posture workload")?;
        std::fs::write(out.join(&files.fence_execution), fence_snapshot(pod)?)?;
        let bundle = live::body(
            node.client
                .post(format!("{base}/execution-receipt"))
                .json(&json!({"artifacts": selection.clone()}))
                .send()
                .await?,
        )
        .await?;
        std::fs::write(out.join(&files.artifacts_bundle), &bundle)?;
        let bundle: serde_json::Value = serde_json::from_slice(&bundle)?;
        let receipt = bundle
            .get("receipt")
            .context("artifact bundle has no receipt")?;
        std::fs::write(
            out.join(&files.receipt),
            serde_json::to_vec_pretty(receipt)?,
        )?;
        for (stream, file) in [("stdout", &files.stdout), ("stderr", &files.stderr)] {
            let bytes = ok(node, &format!("{base}/workload-logs/{stream}")).await?;
            std::fs::write(out.join(file), bytes)?;
        }
        // What the receipt says about the platform: read only to fetch the
        // document it names. Appraising it is the appraiser's job.
        let receipt: nucleus_receipt::Receipt = serde_json::from_value(receipt.clone())?;
        let claim = receipt
            .projections
            .iter()
            .find_map(|p| match p {
                nucleus_receipt::Projection::Ci(body) => Some(body.clone()),
                _ => None,
            })
            .context("receipt carries no execution claim")?;
        let claim: nucleus_ci_verdict::execution::ExecutionClaim = serde_json::from_value(claim)?;
        let node_evidence = match claim.node_platform {
            nucleus_ci_verdict::execution::NodePlatform::Unattested { reason } => {
                NodeEvidence::Unattested { reason }
            }
            nucleus_ci_verdict::execution::NodePlatform::Evidence {
                evidence_sha256,
                epoch,
            } => {
                let file = "node-evidence.json".to_string();
                let bytes = ok(
                    node,
                    &format!("{}/v1/node/evidence/{evidence_sha256}", node.url),
                )
                .await?;
                std::fs::write(out.join(&file), bytes)?;
                NodeEvidence::Evidence {
                    file,
                    sha256: evidence_sha256,
                    epoch,
                }
            }
        };
        Ok(Execution {
            pod,
            create_ms,
            ready_ms,
            exit_ms,
            firecracker,
            node_evidence,
        })
    })
    .await
}

async fn effect(node: &Node, out: &Path, files: &Files, nonce: &str) -> Result<(Uuid, u64)> {
    let (created, create_ms) = create(node, &live::effect_pod_spec(&node.upstream)).await?;
    let pod = created.id;
    then_cancel(node, pod, async {
        live::relay(&created.proxy_addr, nonce).await?;
        let dir = node.state.join("pods").join(pod.to_string());
        let outcomes = dir.join(nucleus_spec::host_effect::outcome::LOG_FILE);
        // The response can reach the guest just before the durable outcome append.
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match std::fs::read_to_string(&outcomes) {
                    Ok(s) if !s.trim().is_empty() => return Ok::<_, anyhow::Error>(()),
                    Ok(_) => {}
                    Err(e) => return Err(e.into()),
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .context("the host recorded no outcome")??;
        std::fs::copy(
            dir.join(nucleus_spec::host_effect::LOG_FILE),
            out.join(&files.host_effects),
        )?;
        std::fs::copy(&outcomes, out.join(&files.host_effect_outcomes))?;
        std::fs::write(out.join(&files.fence_effect), fence_snapshot(pod)?)?;
        Ok((pod, create_ms))
    })
    .await
}

/// Boot the honest eval cell, or record the node's refusal of it. Writes the
/// spec, the [`EvalCellRun`] and, when admitted, the cell's filter table; the
/// console is copied by the caller after cancellation, like the effect pod's.
async fn eval_cell(node: &Node, out: &Path, files: &Files) -> Result<Option<Uuid>> {
    let manifest =
        tokio::task::spawn_blocking(crate::workload_verification::installed_manifest).await??;
    let spec = eval_cell_spec(&manifest)?;
    std::fs::write(
        out.join(&files.eval_cell_spec),
        serde_json::to_vec_pretty(&spec)?,
    )?;
    let started = Instant::now();
    let response = node
        .client
        .post(format!("{}/v1/pods", node.url))
        .timeout(nucleus_spec::boot_budget::POD_CREATE_CLIENT_TIMEOUT)
        .json(&spec)
        .send()
        .await?;
    let status = response.status();
    let bytes = response.bytes().await?;
    let (run, admitted) = if status.is_client_error() {
        let refused = EvalCellRun::Refused {
            status: status.as_u16(),
            reason: String::from_utf8_lossy(&bytes).into_owned(),
        };
        (refused, None)
    } else {
        ensure!(
            status.is_success(),
            "creating the eval cell: HTTP {status}: {}",
            String::from_utf8_lossy(&bytes)
        );
        let created: live::Created = serde_json::from_slice(&bytes)?;
        let pod = created.id;
        let exit = then_cancel(node, pod, async {
            let base = format!("{}/v1/pods/{pod}", node.url);
            let exit = wait_exit(node, &base, started)
                .await
                .context("the eval-cell workload")?;
            std::fs::write(out.join(&files.fence_eval_cell), fence_snapshot(pod)?)?;
            Ok(exit)
        })
        .await?;
        let admitted = EvalCellRun::Admitted {
            pod: pod.to_string(),
            exit_code: exit.exit_code,
        };
        (admitted, Some(pod))
    };
    std::fs::write(out.join(&files.eval_cell), serde_json::to_vec_pretty(&run)?)?;
    Ok(admitted)
}

async fn collect(
    node: &Node,
    bins: &Path,
    out: &Path,
    nonce: &str,
    started: Instant,
    node_ready_ms: u64,
) -> Result<()> {
    let files = Files::standard();
    let key = live::host_key(node, bins).await?;
    std::fs::write(out.join(&files.host_key), format!("{key}\n"))?;
    let pid = node.pid().context("the fixture node has no pid")?;
    let node_bin = process_exe(pid, "/usr/local/bin/nucleus-node")?;
    let run = execution(node, out, &files, nonce).await;
    // The console is diagnostic as much as it is evidence: save it on failure too.
    if let Ok(run) = &run {
        let console = node
            .state
            .join("pods")
            .join(run.pod.to_string())
            .join("firecracker.log");
        std::fs::copy(&console, out.join(&files.guest_console))
            .with_context(|| format!("copying {}", console.display()))?;
    }
    let run = run?;
    let (effect_pod, effect_pod_create_ms) = effect(node, out, &files, nonce).await?;
    let pods = node.state.join("pods");
    copy_console(&pods, effect_pod, &out.join(&files.effect_console))?;
    let (coverage_pod, coverage_ms) = coverage(node, out, &files).await?;
    copy_console(&pods, coverage_pod, &out.join(&files.coverage_console))?;
    let eval_cell = eval_cell(node, out, &files).await?;
    let mut cancelled = vec![run.pod, effect_pod, coverage_pod];
    if let Some(pod) = eval_cell {
        copy_console(&pods, pod, &out.join(&files.eval_cell_console))?;
        cancelled.push(pod);
    }
    // After every pod was cancelled: every comparison any pod's shadow service
    // made has been appended by now.
    gather_disagreements(
        &pods,
        &cancelled,
        &out.join(&files.host_decide_disagreements),
    )?;
    let jailer = Measured {
        path: JAILER.into(),
        sha256: sha256_file(Path::new(JAILER))?,
        how: MeasuredHow::ConfiguredFile,
    };
    let collection = Collection {
        schema: live_boot::SCHEMA.into(),
        nonce: nonce.into(),
        execution_pod: run.pod.to_string(),
        effect_pod: effect_pod.to_string(),
        coverage_pod: coverage_pod.to_string(),
        files,
        measured: vec![node_bin, run.firecracker, jailer],
        node_evidence: run.node_evidence,
        timings: live_boot::Timings {
            node_ready_ms,
            pod_create_ms: run.create_ms,
            guest_proxy_ready_ms: run.ready_ms,
            workload_exit_ms: run.exit_ms,
            effect_pod_create_ms,
            coverage_ms,
            total_ms: millis(started),
        },
    };
    std::fs::write(
        out.join(live_boot::COLLECTION_FILE),
        serde_json::to_vec_pretty(&collection)?,
    )?;
    Ok(())
}

/// The operation-coverage pod (ADR 0014 S2): its calls, then a pause longer
/// than the guest's quiet interval so its telemetry line reaches the console
/// before the VM is killed.
async fn coverage(node: &Node, out: &Path, files: &Files) -> Result<(Uuid, u64)> {
    let started = Instant::now();
    let (created, _) = create(node, &crate::live_boot_coverage::pod_spec(&node.upstream)).await?;
    let pod = created.id;
    then_cancel(node, pod, async {
        let calls = crate::live_boot_coverage::drive(&created.proxy_addr).await?;
        std::fs::write(
            out.join(&files.coverage_calls),
            serde_json::to_vec_pretty(&calls)?,
        )?;
        tokio::time::sleep(Duration::from_secs(1)).await;
        Ok((pod, millis(started)))
    })
    .await
}

/// Copy a pod's guest console into the bundle.
fn copy_console(pods: &Path, pod: Uuid, to: &Path) -> Result<()> {
    let console = pods.join(pod.to_string()).join("firecracker.log");
    std::fs::copy(&console, to).with_context(|| format!("copying {}", console.display()))?;
    Ok(())
}

/// Concatenate each pod's disagreement record into one bundle file. A pod with
/// no disagreement has no record file, which is not an error; the bundle file
/// is written even when it ends up empty, so its absence from a bundle always
/// means it was withheld (ADR 0014 S1).
fn gather_disagreements(pods: &Path, which: &[Uuid], to: &Path) -> Result<()> {
    let mut all = Vec::new();
    for pod in which {
        let record = pods
            .join(pod.to_string())
            .join(nucleus_spec::host_decide_telemetry::DISAGREEMENT_LOG);
        match std::fs::read(&record) {
            Ok(bytes) => {
                all.extend_from_slice(&bytes);
                if !bytes.is_empty() && !bytes.ends_with(b"\n") {
                    all.push(b'\n');
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("reading {}", record.display())),
        }
    }
    std::fs::write(to, all).with_context(|| format!("writing {}", to.display()))
}

fn var(name: &str) -> Result<String> {
    let value = std::env::var(name).with_context(|| format!("missing {name}"))?;
    ensure!(!value.is_empty(), "empty {name}");
    Ok(value)
}

#[tokio::test]
#[ignore = "requires a Linux KVM host; run cargo xtask live-boot-evidence"]
async fn collect_live_boot_evidence() -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "live boot evidence requires Linux"
    );
    let bins = PathBuf::from(var("NUCLEUS_LIVE_BOOT_BIN_DIR")?);
    let node_bin = PathBuf::from(var("NUCLEUS_LIVE_BOOT_NODE_BIN")?);
    let out = PathBuf::from(var("NUCLEUS_LIVE_BOOT_OUT")?);
    let witness = PathBuf::from(var("NUCLEUS_LIVE_BOOT_WITNESS")?);
    let nonce = var("NUCLEUS_LIVE_BOOT_NONCE")?;
    // Extra node arguments, one per line (the node-evidence flags when the
    // host has a TPM). Absent means none.
    let extra: Vec<String> = std::env::var("NUCLEUS_LIVE_BOOT_NODE_ARGS")
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();
    ensure!(out.is_dir(), "{} is not a directory", out.display());
    let started = Instant::now();
    let mut node = Node::start_with(&node_bin, &nonce, &extra).await?;
    let node_ready_ms = millis(started);
    let result = collect(&node, &bins, &out, &nonce, started, node_ready_ms).await;
    let log = node
        .log()
        .unwrap_or_else(|e| format!("could not read the node log: {e}"));
    let diagnostics = result.as_ref().err().map(|_| node.diagnostics());
    node.stop().await?;
    std::fs::write(out.join(Files::standard().node_log), log)?;
    if let Some(diagnostics) = diagnostics {
        result.context(diagnostics)?;
    }
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(witness)?;
    file.write_all(nonce.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_workload_runs_every_probe_and_fails_if_any_failed() {
        let script = workload_script("abc");
        for probe in [
            "nucleus-workload-probe;",
            "nucleus-workload-probe --syscall-filter;",
            "nucleus-workload-probe --run-child;",
            "nucleus-egress-probe;",
            "nucleus-adversary-probe;",
        ] {
            assert!(script.contains(probe), "{probe} missing from {script}");
        }
        for status in ["$w", "$s", "$r", "$e", "$a"] {
            assert!(script.contains(&format!("[ {status} -eq 0 ]")), "{status}");
        }
        assert!(script.contains("'live-boot-evidence abc' > /work/live-boot-note.txt"));
    }
}
