//! SPIKE (PR0 of the microVM host-tier plan): can an Apple `container` with
//! nested virtualization host nucleus-node's Firecracker pods?
//!
//! Historical September 29 measurement harness; not a CI acceptance gate.
//! Read printed result rows: a completed test can report a failed experiment.
//! Nothing here is wired into the CLI. Every step drives the
//! `container` CLI through `std::process::Command` and prints what it saw;
//! results are written up in `docs/findings/microvm-host-apple-container.md`.
//!
//! Gated twice: `#[ignore]`, and `NUCLEUS_MICROVM_HOST_SPIKE=1`. It boots VMs,
//! builds a kernel and needs a Mac with `container` 1.4.1+ running:
//!
//! ```text
//! NUCLEUS_MICROVM_HOST_SPIKE=1 cargo test -p nucleus-cli --test microvm_host_spike \
//!     -- --ignored --nocapture --test-threads=1 <step>
//! ```
//!
//! Steps, in the order they are meant to run: `build_l1_kernel`,
//! `build_microvm_host_image`, `p7_without_virtualization`, `p1_p2_kvm_and_devices`,
//! `p2_minimal_capabilities`, `p3_pod_boots`, `p5_exec_stdio`, `p4_workspace_roundtrip`,
//! `p6_lifecycles` (`NUCLEUS_SPIKE_P6_LOAD=exec|io` adds guest load), `p6b_forced_death`,
//! `cleanup`. The image defaults to the GUEST_RELEASE node (`NUCLEUS_SPIKE_NODE_SOURCE=source`
//! selects a node built from this tree, which cannot boot the 2.2.0 rootfs — see the findings).
//!
//! These measurements were taken when the image carried the 2.2.0 release. The image now
//! carries 2.4.0 (2.3.0 before it), whose release node is mTLS-only like a source-built one,
//! so the HMAC path `node_auth` selects for the release node describes the measured 2.2.0
//! image only; this harness has not been re-run against the 2.3.0 or 2.4.0 image.
//!
//! Safety: everything this creates is named `nucleus-spike-*`, and [`remove`]
//! refuses any other name. It never changes a system-wide `container` property;
//! the L1 kernel is attached per container with `--kernel`.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

const PREFIX: &str = "nucleus-spike-";
const IMAGE: &str = "nucleus-spike-microvm-host:dev";
const HOST: &str = "nucleus-spike-host";
const VOLUME: &str = "nucleus-spike-srv";
const NODE: &str = "https://127.0.0.1:8080";
/// The dev proxy secret baked into the image (`NUCLEUS_NODE_PROXY_AUTH_SECRET`).
const PROXY_SECRET: &str = "00000000000000000000000000000000000000000000000000000000000000a2";

/// Capabilities added over the runtime default when nothing overrides it —
/// the set `p2_minimal_capabilities` measured as sufficient.
const DEFAULT_CAPS: &[&str] = &["CAP_NET_ADMIN", "CAP_SYS_ADMIN", "CAP_SYS_PTRACE"];

fn enabled() -> bool {
    let on = std::env::var("NUCLEUS_MICROVM_HOST_SPIKE").as_deref() == Ok("1");
    if !on {
        eprintln!("skipped: set NUCLEUS_MICROVM_HOST_SPIKE=1 to run the microVM host spike");
    }
    on
}

/// Where build outputs go: `$CARGO_TARGET_TMPDIR/microvm-host-spike`.
fn work_dir() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("microvm-host-spike");
    std::fs::create_dir_all(&dir).expect("create spike work dir");
    dir
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate is two levels below the repo root")
        .to_path_buf()
}

fn l1_kernel() -> PathBuf {
    std::env::var_os("NUCLEUS_SPIKE_L1_KERNEL")
        .map(PathBuf::from)
        .unwrap_or_else(|| work_dir().join("l1").join("linux_arm64").join("Image"))
}

fn caps() -> Vec<String> {
    match std::env::var("NUCLEUS_SPIKE_CAPS") {
        Ok(v) if !v.trim().is_empty() => v.split(',').map(|s| s.trim().to_string()).collect(),
        _ => DEFAULT_CAPS.iter().map(|s| s.to_string()).collect(),
    }
}

fn extra_kernel_args() -> Vec<String> {
    std::env::var("NUCLEUS_SPIKE_KERNEL_ARGS")
        .ok()
        .map(|v| v.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default()
}

// ── running `container` ─────────────────────────────────────────────

#[derive(Debug)]
struct Out {
    code: Option<i32>,
    stdout: String,
    stderr: String,
    elapsed: Duration,
}

impl Out {
    fn ok(&self) -> bool {
        self.code == Some(0)
    }
    fn text(&self) -> String {
        format!("{}{}", self.stdout, self.stderr).trim().to_string()
    }
}

fn container(args: &[&str]) -> Out {
    container_with_stdin(args, None)
}

fn container_with_stdin(args: &[&str], stdin: Option<&[u8]>) -> Out {
    let started = Instant::now();
    let mut child = Command::new("container")
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("`container` CLI on PATH");
    if let Some(bytes) = stdin {
        let mut pipe = child.stdin.take().expect("piped stdin");
        let bytes = bytes.to_vec();
        std::thread::spawn(move || {
            let _ = pipe.write_all(&bytes);
        });
    }
    let output = child.wait_with_output().expect("wait for `container`");
    Out {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        elapsed: started.elapsed(),
    }
}

/// `container exec <name> <argv...>` — argv, never a shell string, unless the
/// caller asks for `sh -c` explicitly.
fn exec(name: &str, argv: &[&str]) -> Out {
    let mut args = vec!["exec", name];
    args.extend_from_slice(argv);
    container(&args)
}

fn sh(name: &str, script: &str) -> Out {
    exec(name, &["sh", "-c", script])
}

/// How to start a spike host container.
#[derive(Clone)]
struct HostOpts {
    name: String,
    virtualization: bool,
    kernel: Option<PathBuf>,
    kernel_args: Vec<String>,
    caps: Vec<String>,
    volume: bool,
    /// Run `sleep infinity` instead of the node, to probe the host alone.
    idle: bool,
}

impl HostOpts {
    fn node(name: &str) -> Self {
        Self {
            name: name.to_string(),
            virtualization: true,
            kernel: Some(l1_kernel()),
            kernel_args: extra_kernel_args(),
            caps: caps(),
            volume: true,
            idle: false,
        }
    }
}

fn run_host(o: &HostOpts) -> Out {
    assert!(o.name.starts_with(PREFIX), "refusing to create {}", o.name);
    let mut args: Vec<String> = [
        "run", "-d", "--init", "--name", &o.name, "-c", "4", "-m", "4g",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if o.virtualization {
        args.push("--virtualization".into());
    }
    if let Some(k) = &o.kernel {
        args.push("--kernel".into());
        args.push(k.display().to_string());
    }
    for a in &o.kernel_args {
        args.push("--kernel-arg".into());
        args.push(a.clone());
    }
    for c in &o.caps {
        args.push("--cap-add".into());
        args.push(c.clone());
    }
    if o.volume {
        args.push("-v".into());
        args.push(format!("{VOLUME}:/srv"));
    }
    if o.idle {
        args.push("--entrypoint".into());
        args.push("sleep".into());
    }
    args.push(IMAGE.into());
    if o.idle {
        args.push("infinity".into());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    container(&refs)
}

/// Stop and delete one of OUR containers. Refuses any other name.
fn remove(name: &str) {
    assert!(name.starts_with(PREFIX), "refusing to touch {name}");
    let _ = container(&["stop", "-t", "2", name]);
    let _ = container(&["delete", "--force", name]);
}

fn ensure_volume() {
    let _ = container(&["volume", "create", VOLUME]);
}

/// `container list --all --format json`, reduced to our host's status string.
fn host_state(name: &str) -> Result<String, String> {
    let out = container(&["list", "--all", "--format", "json"]);
    if !out.ok() {
        return Err(format!("container list failed: {}", out.text()));
    }
    parse_host_state(&out.stdout, name)
}

// A-1: failure to observe a VM must not count as a measured VM death.
fn parse_host_state(json: &str, name: &str) -> Result<String, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let entries = v.as_array().ok_or("container list is not an array")?;
    for c in entries {
        let id = c
            .pointer("/configuration/id")
            .or_else(|| c.get("id"))
            .and_then(|v| v.as_str())
            .ok_or("container entry has no id")?;
        if id == name {
            return c
                .pointer("/status/state")
                .and_then(|s| s.as_str())
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .ok_or_else(|| "container entry has no state".to_string());
        }
    }
    Ok("absent".to_string())
}

#[test]
fn status_observation_failure_is_not_a_vm_death() {
    for json in ["not json", "null", "{}", "[{}]", r#"[{"id":"host"}]"#] {
        assert!(parse_host_state(json, "host").is_err(), "{json}");
    }
    assert_eq!(parse_host_state("[]", "host").unwrap(), "absent");
    for state in ["running", "stopped"] {
        let json = serde_json::json!([{"configuration":{"id":"host"},"status":{"state":state}}]);
        assert_eq!(parse_host_state(&json.to_string(), "host").unwrap(), state);
    }
}

fn kv(text: &str, key: &str) -> Option<String> {
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}=")).map(str::to_string))
}

fn row(id: &str, verdict: &str, detail: &str) {
    println!("| {id:<4} | {verdict:<5} | {detail}");
}

// ── node access from inside the container ───────────────────────────

/// Mint an operator client certificate against the node's CA, inside the
/// container (the node's listener is mTLS-only). Idempotent.
fn mint_client_cert(name: &str) -> Out {
    sh(
        name,
        "set -e; cd /srv; test -s cli.pem && exit 0; \
         test -s state/ca/ca-key.pem; \
         openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
           -keyout cli-key.pem -subj /CN=cli -out cli.csr 2>/dev/null; \
         printf 'subjectAltName=URI:spiffe://nucleus.local/ns/system/sa/cli\\n\
extendedKeyUsage=clientAuth\\nbasicConstraints=CA:FALSE\\n' > cli.ext; \
         openssl x509 -req -in cli.csr -CA state/ca/ca-cert.pem -CAkey state/ca/ca-key.pem \
           -CAcreateserial -days 2 -extfile cli.ext -out cli.pem 2>/dev/null",
    )
}

/// How the node in the image authenticates its API callers.
///
/// A node built from this tree is mTLS-only (Move B). The GUEST_RELEASE 2.2.0
/// node (`NODE_SOURCE=release`) predates that: plaintext HTTP with the
/// `x-nucleus-*` HMAC headers over `"{ts}.{actor}.{body}"`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum NodeAuth {
    Mtls,
    Hmac,
}

fn node_auth() -> NodeAuth {
    match std::env::var("NUCLEUS_SPIKE_NODE_SOURCE").as_deref() {
        Ok("source") => NodeAuth::Mtls,
        _ => NodeAuth::Hmac,
    }
}

/// The dev node secret baked into the image (`NUCLEUS_NODE_AUTH_SECRET`).
const NODE_SECRET: &str = "00000000000000000000000000000000000000000000000000000000000000a1";

fn hmac_hex(message: &[u8]) -> String {
    use hmac::{KeyInit, Mac};
    let mut mac =
        hmac::Hmac::<Sha256>::new_from_slice(NODE_SECRET.as_bytes()).expect("any key length");
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}

/// `curl` the node API from inside the container. Under mTLS `-k` is used
/// because the node's server certificate carries a SPIFFE URI SAN, not an IP
/// SAN; the client certificate is still presented and checked by the node.
fn node_api(name: &str, method: &str, path: &str, body: Option<&str>) -> (u16, String) {
    let mut argv: Vec<String> = [
        "curl",
        "-sk",
        "--max-time",
        "120",
        "-X",
        method,
        "-w",
        "\n%{http_code}",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let url = match node_auth() {
        NodeAuth::Mtls => {
            argv.extend(
                ["--cert", "/srv/cli.pem", "--key", "/srv/cli-key.pem"].map(str::to_string),
            );
            format!("{NODE}{path}")
        }
        NodeAuth::Hmac => {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_secs()
                .to_string();
            let sig = hmac_hex(format!("{ts}.spike.{}", body.unwrap_or("")).as_bytes());
            argv.extend([
                "-H".to_string(),
                format!("x-nucleus-timestamp: {ts}"),
                "-H".to_string(),
                "x-nucleus-actor: spike".to_string(),
                "-H".to_string(),
                format!("x-nucleus-signature: {sig}"),
            ]);
            format!("http://127.0.0.1:8080{path}")
        }
    };
    if let Some(b) = body {
        argv.extend(
            ["-H", "content-type: application/json", "--data-binary", b].map(str::to_string),
        );
    }
    argv.push(url);
    let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
    let out = exec(name, &refs);
    let (body, code) = out.stdout.rsplit_once('\n').unwrap_or(("", &out.stdout));
    (code.trim().parse().unwrap_or(0), body.to_string())
}

/// A writable copy of the pinned rootfs, on the /srv volume.
///
/// Why not the pinned artifact with `read_only: true`: the GUEST_RELEASE 2.2.0
/// rootfs predates the guest putting its SVID on tmpfs, so its guest-init
/// fails "failed to create identity directory: Read-only file system" and the
/// VMM exits ~3 s in. Measured here, first boot. A writable rootfs is
/// hard-linked into the jail, so it must share /srv with `/srv/jailer`; one
/// copy serves every (sequential) pod of a run.
const ROOTFS_RW: &str = "/srv/rootfs-rw.ext4";

fn ensure_rw_rootfs(name: &str) -> Out {
    sh(
        name,
        &format!(
            "test -s {ROOTFS_RW} || cp --sparse=always /var/lib/nucleus/artifacts/rootfs.ext4 {ROOTFS_RW}"
        ),
    )
}

/// Wait until the node answers `/v1/health` over mTLS. Returns the wait.
fn wait_node_healthy(name: &str, timeout: Duration) -> Result<Duration, String> {
    let started = Instant::now();
    let mut last = String::new();
    while started.elapsed() < timeout {
        let m = match node_auth() {
            NodeAuth::Mtls => mint_client_cert(name),
            NodeAuth::Hmac => sh(name, "true"),
        };
        if m.ok() {
            let (code, body) = node_api(name, "GET", "/v1/health", None);
            if code == 200 {
                let rw = ensure_rw_rootfs(name);
                if !rw.ok() {
                    return Err(format!("rw rootfs copy: {}", rw.text()));
                }
                return Ok(started.elapsed());
            }
            last = format!("health {code}: {body}");
        } else {
            last = format!("cert: {}", m.text());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let logs = container(&["logs", name]);
    let tail: Vec<&str> = logs.stdout.lines().rev().take(15).collect();
    Err(format!(
        "node not healthy after {timeout:?}; last: {last}; log tail:\n{}",
        tail.into_iter().rev().collect::<Vec<_>>().join("\n")
    ))
}

/// A pod spec. There is no `workload` field on purpose: the 2.2.0 rootfs bakes
/// `/etc/nucleus/pod.yaml`, and guest-init prefers a baked spec over the one
/// the host serves, so a submitted workload is silently ignored ("[workload]
/// no workload configured"). P4 bakes its workload into its own rootfs copy.
fn pod_spec(tag: &str, scratch: Option<&str>, rootfs: Option<&str>) -> String {
    let scratch = scratch
        .map(|p| format!(r#","scratch_path":"{p}""#))
        .unwrap_or_default();
    let rootfs = rootfs.unwrap_or(ROOTFS_RW);
    format!(
        r#"{{"apiVersion":"nucleus/v1","kind":"Pod",
            "metadata":{{"name":"spike-{tag}"}},
            "spec":{{"work_dir":"/work","timeout_seconds":600,
              "policy":{{"type":"profile","name":"codegen"}},
              "image":{{"kernel_path":"/var/lib/nucleus/artifacts/vmlinux",
                        "rootfs_path":"{rootfs}",
                        "read_only":false{scratch}}},
              "vsock":{{"guest_cid":3,"port":5005}}}}}}"#
    )
}

struct Pod {
    id: String,
    proxy: String,
    create: Duration,
}

fn create_pod(name: &str, spec: &str) -> Result<Pod, String> {
    let started = Instant::now();
    let (code, body) = node_api(name, "POST", "/v1/pods", Some(spec));
    let create = started.elapsed();
    if code != 200 && code != 201 {
        return Err(format!("create {code}: {}", body.trim()));
    }
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("create body {e}: {body}"))?;
    let id = v["id"].as_str().ok_or("no id")?.to_string();
    let proxy = v["proxy_addr"].as_str().ok_or("no proxy_addr")?.to_string();
    let proxy = if proxy.starts_with("http") {
        proxy
    } else {
        format!("http://{proxy}")
    };
    Ok(Pod { id, proxy, create })
}

fn proxy_health(name: &str, pod: &Pod) -> (bool, String) {
    let out = exec(
        name,
        &[
            "curl",
            "-s",
            "--max-time",
            "10",
            &format!("{}/v1/health", pod.proxy),
        ],
    );
    (out.ok() && out.stdout.contains("sandbox_proof"), out.text())
}

fn wait_proxy_healthy(
    name: &str,
    pod: &Pod,
    timeout: Duration,
) -> Result<(Duration, String), String> {
    let started = Instant::now();
    let mut last = String::new();
    while started.elapsed() < timeout {
        let (ok, body) = proxy_health(name, pod);
        if ok {
            return Ok((started.elapsed(), body));
        }
        last = body;
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(format!("proxy not healthy after {timeout:?}: {last}"))
}

fn cancel_pod(name: &str, pod: &Pod) -> (u16, String) {
    node_api(name, "POST", &format!("/v1/pods/{}/cancel", pod.id), None)
}

/// Wait for `marker` on the pod's console. The 2.2.0 node has no
/// `workload-result` route; its proxy drains workload stdout to the console as
/// `[workload] <line>`, so the workload announces its own completion.
fn wait_console_marker(
    name: &str,
    pod: &Pod,
    marker: &str,
    timeout: Duration,
) -> Result<Duration, String> {
    let started = Instant::now();
    let log = format!("/srv/state/pods/{}/firecracker.log", pod.id);
    while started.elapsed() < timeout {
        if exec(name, &["grep", "-qF", marker, &log]).ok() {
            return Ok(started.elapsed());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err(format!("no {marker:?} on the console after {timeout:?}"))
}

/// A firecracker log line mentioning the pod id's state dir, for diagnosis.
fn pod_console_tail(name: &str, pod: &Pod) -> String {
    sh(
        name,
        &format!(
            "tail -n 25 /srv/state/pods/{}/firecracker.log 2>/dev/null || ls /srv/state/pods",
            pod.id
        ),
    )
    .text()
}

// ── steps ───────────────────────────────────────────────────────────

/// Deliverable 1: build the L1 kernel and export `Image` + `config`.
#[test]
#[ignore = "spike: builds a kernel with `container build`"]
fn build_l1_kernel() {
    if !enabled() {
        return;
    }
    let base = std::env::var_os("NUCLEUS_SPIKE_BASE_KERNEL")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var("HOME").expect("HOME")).join(
                "Library/Application Support/com.apple.container/kernels/vmlinux-6.18.35-197-debug",
            )
        });
    let ctx = work_dir().join("l1-ctx");
    std::fs::create_dir_all(&ctx).expect("ctx");
    std::fs::copy(&base, ctx.join("base-kernel")).expect("copy base kernel");
    std::fs::copy(
        repo_root().join("docker/l1-kernel.fragment"),
        ctx.join("l1-kernel.fragment"),
    )
    .expect("copy fragment");
    let out_dir = work_dir().join("l1");
    let file = repo_root().join("docker/Containerfile.l1-kernel");
    let out = container(&[
        "build",
        "-c",
        "8",
        "-m",
        "12g",
        "--progress",
        "plain",
        "-f",
        &file.display().to_string(),
        "-o",
        &format!("type=local,dest={}", out_dir.display()),
        &ctx.display().to_string(),
    ]);
    println!(
        "{}",
        out.stderr
            .lines()
            .rev()
            .take(20)
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(out.ok(), "kernel build failed: {}", out.text());
    // `-o type=local` splits output per platform.
    let image = out_dir.join("linux_arm64").join("Image");
    let bytes = std::fs::read(&image).expect("Image exported");
    println!(
        "L1 kernel built in {:.0?}: {} ({} bytes, sha256 {})",
        out.elapsed,
        image.display(),
        bytes.len(),
        hex::encode(Sha256::digest(&bytes))
    );
}

/// Deliverable 2: build the microVM host image from this tree.
#[test]
#[ignore = "spike: builds the microvm-host image with `container build`"]
fn build_microvm_host_image() {
    if !enabled() {
        return;
    }
    // A staged flat context, never the repository root: Apple Container drops
    // nested files from a directory `COPY` (#3206).
    let context = std::env::temp_dir().join(format!(
        "nucleus-spike-release-context-{}",
        std::process::id()
    ));
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let staged = Command::new(cargo)
        .current_dir(repo_root())
        .args(["run", "--quiet", "-p", "xtask", "--"])
        .arg("microvm-host-release-context")
        .arg("--out")
        .arg(&context)
        .status()
        .expect("running xtask");
    assert!(staged.success(), "staging the release context: {staged}");
    let mut args = vec![
        "build".to_string(),
        "-c".into(),
        "8".into(),
        "-m".into(),
        "12g".into(),
        "--progress".into(),
        "plain".into(),
        "-f".into(),
        context.join("Containerfile").display().to_string(),
        "-t".into(),
        IMAGE.into(),
    ];
    if let Ok(src) = std::env::var("NUCLEUS_SPIKE_NODE_SOURCE") {
        args.push("--build-arg".into());
        args.push(format!("NODE_SOURCE={src}"));
    }
    args.push(context.display().to_string());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = container(&refs);
    println!(
        "{}",
        out.stderr
            .lines()
            .rev()
            .take(20)
            .collect::<Vec<_>>()
            .join("\n")
    );
    assert!(out.ok(), "image build failed: {}", out.text());
    println!("microvm-host image built in {:.0?}", out.elapsed);
    println!("{}", container(&["image", "list"]).stdout);
}

/// P7: without `--virtualization` there is no /dev/kvm, and the node says so.
#[test]
#[ignore = "spike: boots Apple containers"]
fn p7_without_virtualization() {
    if !enabled() {
        return;
    }
    ensure_volume();
    let name = "nucleus-spike-p7";
    remove(name);
    let mut o = HostOpts::node(name);
    o.virtualization = false;
    // A block volume attaches to one running container at a time (VZErrorDomain
    // Code=2 "The storage device attachment is invalid" otherwise), and the
    // long-lived host holds it. /srv on the container rootfs serves here.
    o.volume = false;
    let run = run_host(&o);
    assert!(run.ok(), "run: {}", run.text());
    let probe = exec(name, &["kvm-probe"]);
    // What a preflight can read to say WHY: the exception level the kernel
    // booted at (EL2 is what KVM needs) and KVM's own init line.
    let el = sh(name, "dmesg | grep -iE 'started at EL|kvm \\['");
    println!(
        "probe (L1 kernel, no --virtualization):\n{}\n{}",
        probe.text(),
        el.text()
    );
    let healthy = wait_node_healthy(name, Duration::from_secs(60));
    let create = match &healthy {
        Ok(_) => match create_pod(name, &pod_spec("p7", None, None)) {
            Ok(pod) => {
                let _ = cancel_pod(name, &pod);
                "UNEXPECTED: pod created".to_string()
            }
            Err(e) => e,
        },
        Err(e) => format!("node never healthy: {e}"),
    };
    println!("pod create without KVM: {create}");
    remove(name);

    // The default kernel WITH --virtualization, to pin down the premise that
    // the runtime's own kernel is the reason (not the flag).
    let name2 = "nucleus-spike-p7b";
    remove(name2);
    let mut o2 = HostOpts::node(name2);
    o2.kernel = None;
    o2.idle = true;
    o2.volume = false;
    let run2 = run_host(&o2);
    assert!(run2.ok(), "run: {}", run2.text());
    let probe2 = exec(name2, &["kvm-probe"]);
    let cfg = sh(
        name2,
        "zcat /proc/config.gz | grep -E '^(# )?CONFIG_(VIRTUALIZATION|KVM|VHOST_VSOCK)[ =]'",
    );
    println!(
        "probe (default kernel, --virtualization):\n{}\n{}",
        probe2.text(),
        cfg.text()
    );
    remove(name2);

    let kvm_absent = probe.text().contains("open /dev/kvm=err");
    let names_kvm = create.contains("/dev/kvm");
    row(
        "P7",
        if kvm_absent && names_kvm {
            "PASS"
        } else {
            "FAIL"
        },
        &format!("kvm absent={kvm_absent}; diagnostic names /dev/kvm={names_kvm}: {create}"),
    );
}

/// P1 + P2 (devices, cgroup2): the L1 kernel under `--virtualization`.
#[test]
#[ignore = "spike: boots Apple containers"]
fn p1_p2_kvm_and_devices() {
    if !enabled() {
        return;
    }
    let name = "nucleus-spike-p1";
    remove(name);
    let mut o = HostOpts::node(name);
    o.idle = true;
    o.volume = false;
    let run = run_host(&o);
    assert!(run.ok(), "run: {}", run.text());
    let probe = exec(name, &["kvm-probe"]);
    let facts = sh(
        name,
        "echo uname=$(uname -r); echo cmdline=$(cat /proc/cmdline); \
         zcat /proc/config.gz | grep -E '^CONFIG_(VIRTUALIZATION|KVM|VHOST|VHOST_VSOCK|BRIDGE_NETFILTER|TUN)='; \
         ls -l /dev/kvm /dev/vhost-vsock /dev/net/tun 2>&1; \
         grep -E '^Cap(Eff|Bnd)' /proc/self/status; \
         echo cgroup_fs=$(stat -fc %T /sys/fs/cgroup); \
         echo controllers=$(cat /sys/fs/cgroup/cgroup.controllers); \
         echo subtree=$(cat /sys/fs/cgroup/cgroup.subtree_control); \
         mkdir /sys/fs/cgroup/nucleus-spike-probe && echo cgroup_mkdir=ok && \
           echo cpuset_cpus=$(cat /sys/fs/cgroup/nucleus-spike-probe/cpuset.cpus.effective 2>&1) && \
           rmdir /sys/fs/cgroup/nucleus-spike-probe; \
         echo br_nf=$(cat /proc/sys/net/bridge/bridge-nf-call-iptables 2>&1); \
         dmesg 2>&1 | grep -iE 'kvm|hyp|el2|vgic' | head -20",
    );
    println!("{}\n{}", probe.text(), facts.text());
    remove(name);

    let api = kv(&probe.stdout, "kvm_api_version");
    let p1 = probe.ok() && api.as_deref() == Some("12");
    row(
        "P1",
        if p1 { "PASS" } else { "FAIL" },
        &format!(
            "api={api:?} create_vm={:?} create_vcpu={:?} ipa_bits={:?} kernel_args={:?}",
            kv(&probe.stdout, "kvm_create_vm"),
            kv(&probe.stdout, "kvm_create_vcpu"),
            kv(&probe.stdout, "kvm_max_ipa_bits"),
            o.kernel_args
        ),
    );
    let t = facts.text();
    let devices = probe.stdout.contains("open /dev/vhost-vsock=ok")
        && probe.stdout.contains("open /dev/net/tun=ok");
    let cgroup = t.contains("cgroup_fs=cgroup2")
        && t.contains("cgroup_mkdir=ok")
        && ["cpuset", "cpu", "memory"]
            .iter()
            .all(|c| kv(&t, "controllers").is_some_and(|l| l.split(' ').any(|x| x == *c)));
    row(
        "P2a",
        if devices && cgroup { "PASS" } else { "FAIL" },
        &format!(
            "vhost-vsock+tun={devices} cgroup2 delegable={cgroup} controllers={:?} subtree={:?}",
            kv(&t, "controllers"),
            kv(&t, "subtree")
        ),
    );
}

/// One full pod boot on a fresh host container with `caps`. Returns the
/// outcome and a short reason.
fn boot_trial(tag: &str, caps: &[String]) -> (bool, String) {
    let name = format!("nucleus-spike-cap-{tag}");
    remove(&name);
    let mut o = HostOpts::node(&name);
    o.caps = caps.to_vec();
    o.volume = false;
    let run = run_host(&o);
    if !run.ok() {
        return (false, format!("run: {}", run.text()));
    }
    let result = (|| {
        wait_node_healthy(&name, Duration::from_secs(90))?;
        let pod = create_pod(&name, &pod_spec(tag, None, None))?;
        let health = wait_proxy_healthy(&name, &pod, Duration::from_secs(60));
        let console = pod_console_tail(&name, &pod);
        let _ = cancel_pod(&name, &pod);
        health
            .map(|(d, _)| format!("proxy healthy in {d:.1?}"))
            .map_err(|e| format!("{e}\nconsole:\n{console}"))
    })();
    remove(&name);
    match result {
        Ok(s) => (true, s),
        Err(e) => (false, e),
    }
}

/// P2 (capabilities): leave-one-out over the added set, starting from ALL.
#[test]
#[ignore = "spike: boots Apple containers and pods"]
fn p2_minimal_capabilities() {
    if !enabled() {
        return;
    }
    ensure_volume();
    let default_caps = {
        let name = "nucleus-spike-capdefault";
        remove(name);
        let mut o = HostOpts::node(name);
        o.caps = vec![];
        o.idle = true;
        o.volume = false;
        assert!(run_host(&o).ok());
        let s = sh(name, "grep -E '^Cap(Eff|Bnd)' /proc/self/status").text();
        remove(name);
        s
    };
    println!("runtime default capabilities:\n{default_caps}");

    let all = boot_trial("all", &["ALL".to_string()]);
    println!("ALL: {} — {}", all.0, all.1);
    let none = boot_trial("none", &[]);
    println!("no --cap-add: {} — {}", none.0, none.1);

    let candidates: Vec<String> = std::env::var("NUCLEUS_SPIKE_CAP_CANDIDATES")
        .unwrap_or_else(|_| "CAP_NET_ADMIN,CAP_SYS_ADMIN,CAP_SYS_PTRACE,CAP_SYS_RESOURCE".into())
        .split(',')
        .map(str::to_string)
        .collect();
    let full = boot_trial("cands", &candidates);
    println!("candidates {candidates:?}: {} — {}", full.0, full.1);
    let mut needed = Vec::new();
    for (i, c) in candidates.iter().enumerate() {
        let rest: Vec<String> = candidates.iter().filter(|x| *x != c).cloned().collect();
        let (ok, why) = boot_trial(&format!("drop{i}"), &rest);
        println!("without {c}: {ok} — {}", why.lines().next().unwrap_or(""));
        if !ok {
            needed.push(c.clone());
        }
    }
    let minimal = boot_trial("minimal", &needed);
    println!("minimal {needed:?}: {} — {}", minimal.0, minimal.1);
    row(
        "P2b",
        if minimal.0 { "PASS" } else { "FAIL" },
        &format!(
            "minimal --cap-add = {needed:?} (ALL ok={}, none ok={})",
            all.0, none.0
        ),
    );
}

/// Start the long-lived spike host unless it is already running, and wait for
/// its node. Returns (`container run` time, node-ready wait) when it started one.
fn ensure_host() -> Option<(Duration, Duration)> {
    ensure_volume();
    if host_state(HOST).expect("observe spike host state") == "running" {
        wait_node_healthy(HOST, Duration::from_secs(120)).expect("node healthy");
        return None;
    }
    remove(HOST);
    let run = run_host(&HostOpts::node(HOST));
    assert!(run.ok(), "run: {}", run.text());
    let wait = wait_node_healthy(HOST, Duration::from_secs(120)).expect("node healthy");
    Some((run.elapsed, wait))
}

/// P3: the node boots a Firecracker pod and the pod's tool-proxy answers.
#[test]
#[ignore = "spike: boots Apple containers and pods"]
fn p3_pod_boots() {
    if !enabled() {
        return;
    }
    if let Some((run, wait)) = ensure_host() {
        println!("`container run` {run:.1?}, then node healthy +{wait:.1?}");
    }
    let pod = create_pod(HOST, &pod_spec("p3", None, None)).expect("P3 pod create");
    match wait_proxy_healthy(HOST, &pod, Duration::from_secs(60)) {
        Ok((d, body)) => row(
            "P3",
            "PASS",
            &format!(
                "create {:.1?}, proxy healthy +{d:.1?}: {}",
                pod.create,
                body.chars().take(160).collect::<String>()
            ),
        ),
        Err(e) => row(
            "P3",
            "FAIL",
            &format!("{e}\n{}", pod_console_tail(HOST, &pod)),
        ),
    }
    let _ = cancel_pod(HOST, &pod);
}

/// One `container exec -i` transfer, killed after `limit` if it wedges.
struct Transfer {
    bytes_back: usize,
    exact: bool,
    finished: bool,
    elapsed: Duration,
}

fn exec_transfer(argv: &[&str], payload: Vec<u8>, limit: Duration) -> Transfer {
    let want = Sha256::digest(&payload);
    let started = Instant::now();
    let mut args = vec!["exec", "-i", HOST];
    args.extend_from_slice(argv);
    let mut child = Command::new("container")
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("exec -i");
    let mut stdin = child.stdin.take().expect("stdin");
    std::thread::spawn(move || {
        // Dropping stdin at the end is the EOF under test.
        let _ = stdin.write_all(&payload);
    });
    let mut stdout = child.stdout.take().expect("stdout");
    let reader = std::thread::spawn(move || {
        let mut got = Vec::new();
        let _ = stdout.read_to_end(&mut got);
        got
    });
    let mut finished = false;
    while started.elapsed() < limit {
        if let Ok(Some(_)) = child.try_wait() {
            finished = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if !finished {
        let _ = child.kill();
    }
    let _ = child.wait();
    if !finished {
        // Killing the host-side client does NOT end the in-container
        // process (measured): reap it so the next transfer starts clean.
        let _ = sh(HOST, &format!("pkill -x {}", argv[0]));
    }
    let elapsed = started.elapsed();
    let got = reader.join().expect("reader");
    Transfer {
        bytes_back: got.len(),
        exact: finished && Sha256::digest(&got) == want,
        finished,
        elapsed,
    }
}

/// P5: `container exec -i` as the stdio transport — bytes, EOF, and MCP.
#[test]
#[ignore = "spike: boots Apple containers and pods"]
fn p5_exec_stdio() {
    if !enabled() {
        return;
    }
    ensure_host();
    let mut summary = Vec::new();
    let mut all_exact = true;
    for mib in [1usize, 2, 4, 8, 10] {
        let mut payload = vec![0u8; mib * 1024 * 1024];
        rand::fill(&mut payload[..]);
        // Streaming: `cat` writes stdout while stdin is still arriving.
        let t = exec_transfer(&["cat"], payload.clone(), Duration::from_secs(30));
        println!(
            "exec -i cat {mib:>2} MiB: finished={} exact={} back={} in {:.2?}",
            t.finished, t.exact, t.bytes_back, t.elapsed
        );
        all_exact &= t.exact;
        summary.push(format!(
            "{mib}MiB cat={}",
            if t.exact { "ok" } else { "WEDGED" }
        ));
        // Store-and-forward: stdout only after stdin EOF.
        let s = exec_transfer(
            &["sh", "-c", "cat > /tmp/p5.bin && cat /tmp/p5.bin"],
            payload,
            Duration::from_secs(30),
        );
        println!(
            "exec -i store-and-forward {mib:>2} MiB: finished={} exact={} back={} in {:.2?}",
            s.finished, s.exact, s.bytes_back, s.elapsed
        );
        summary.push(format!(
            "{mib}MiB s&f={}",
            if s.exact { "ok" } else { "FAIL" }
        ));
    }
    row(
        "P5a",
        if all_exact { "PASS" } else { "FAIL" },
        &summary.join(", "),
    );

    let pod = create_pod(HOST, &pod_spec("p5", None, None)).expect("P5 pod create");
    let health = wait_proxy_healthy(HOST, &pod, Duration::from_secs(60));
    let mcp = match health {
        Ok(_) => (0..5).map(|_| mcp_roundtrip(&pod)).collect::<Vec<_>>(),
        Err(e) => vec![Err(e)],
    };
    for m in &mcp {
        println!("mcp: {m:?}");
    }
    let ok = mcp.iter().all(Result::is_ok);
    row(
        "P5b",
        if ok { "PASS" } else { "FAIL" },
        mcp.first()
            .map(|m| m.clone().unwrap_or_else(|e| e))
            .as_deref()
            .unwrap_or(""),
    );
    let _ = cancel_pod(HOST, &pod);
}

/// P4: seed -> guest edit -> harvest, after a clean end and after SIGKILL.
#[test]
#[ignore = "spike: boots Apple containers and pods"]
fn p4_workspace_roundtrip() {
    if !enabled() {
        return;
    }
    ensure_host();
    for (tag, unclean) in [("p4-clean", false), ("p4-kill", true)] {
        let r = workspace_roundtrip(tag, unclean);
        row(
            if unclean { "P4b" } else { "P4a" },
            if r.is_ok() { "PASS" } else { "FAIL" },
            &r.unwrap_or_else(|e| e),
        );
    }
}

fn mcp_roundtrip(pod: &Pod) -> Result<String, String> {
    let started = Instant::now();
    let mut child = Command::new("container")
        .args([
            "exec",
            "-i",
            HOST,
            "nucleus-mcp",
            "--proxy-url",
            &pod.proxy,
            "--auth-secret",
            PROXY_SECRET,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut stdin = child.stdin.take().ok_or("stdin")?;
    let mut lines = BufReader::new(child.stdout.take().ok_or("stdout")?).lines();
    let send = |stdin: &mut std::process::ChildStdin, v: serde_json::Value| {
        writeln!(stdin, "{v}").and_then(|_| stdin.flush())
    };
    send(
        &mut stdin,
        serde_json::json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2024-11-05","capabilities":{},
            "clientInfo":{"name":"spike","version":"0"}}}),
    )
    .map_err(|e| e.to_string())?;
    let init = lines
        .next()
        .ok_or("no initialize reply")?
        .map_err(|e| e.to_string())?;
    let t_init = started.elapsed();
    send(
        &mut stdin,
        serde_json::json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .map_err(|e| e.to_string())?;
    let t_list_start = Instant::now();
    send(
        &mut stdin,
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    )
    .map_err(|e| e.to_string())?;
    let list = lines
        .next()
        .ok_or("no tools/list reply")?
        .map_err(|e| e.to_string())?;
    let t_list = t_list_start.elapsed();
    drop(stdin);
    let status = child.wait().map_err(|e| e.to_string())?;
    let v: serde_json::Value = serde_json::from_str(&list).map_err(|e| format!("{e}: {list}"))?;
    let tools = v
        .pointer("/result/tools")
        .and_then(|t| t.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    if !status.success() || !init.contains("\"result\"") || tools == 0 {
        return Err(format!("init={init} list={list}"));
    }
    Ok(format!(
        "initialize {t_init:.0?} (incl. exec spawn), tools/list {t_list:.0?}, {tools} tools, mcp exit after EOF={status}"
    ))
}

/// A private rootfs copy whose baked `/etc/nucleus/pod.yaml` runs `script`
/// (single-quote free) as the workload. See [`pod_spec`] for why it must be
/// baked rather than submitted.
fn bake_workload_rootfs(tag: &str, script: &str) -> Result<String, String> {
    assert!(
        !script.contains('\''),
        "script is embedded in a YAML '' scalar"
    );
    let rootfs = format!("/srv/rootfs-{tag}.ext4");
    let baked = sh(
        HOST,
        &format!("debugfs -R 'cat /etc/nucleus/pod.yaml' {ROOTFS_RW} 2>/dev/null"),
    );
    let yaml = format!(
        "{}  workload:\n    command: /bin/sh\n    args:\n      - -c\n      - '{script}'\n",
        baked.stdout
    );
    let staged = format!("/tmp/pod-{tag}.yaml");
    let _ = container_with_stdin(
        &["exec", "-i", HOST, "sh", "-c", &format!("cat > {staged}")],
        Some(yaml.as_bytes()),
    );
    let bake = sh(
        HOST,
        &format!(
            "set -e; cp --sparse=always {ROOTFS_RW} {rootfs}; \
             debugfs -w -R 'rm /etc/nucleus/pod.yaml' {rootfs}; \
             debugfs -w -R 'write {staged} /etc/nucleus/pod.yaml' {rootfs}"
        ),
    );
    if bake.ok() {
        Ok(rootfs)
    } else {
        Err(format!("bake workload: {}", bake.text()))
    }
}

/// Seed a scratch image, let the guest edit it, harvest after the pod ends.
fn workspace_roundtrip(tag: &str, unclean: bool) -> Result<String, String> {
    let img = format!("/srv/work/{tag}.ext4");
    // `mkfs.ext4 -d` copies host ownership verbatim. The guest workload runs as
    // `nobody` (65534) and guest-init chowns only the /work root, so a seed
    // left root-owned is readable but not editable — measured: "rm: cannot
    // remove '/work/src/main.rs': Permission denied". Seed as the guest uid.
    let seed = sh(
        HOST,
        &format!(
            "set -e; rm -rf /tmp/seed-{tag} {img}; mkdir -p /tmp/seed-{tag}/src /srv/work; \
             echo seeded-{tag} > /tmp/seed-{tag}/seed.txt; echo 'fn main() {{}}' > /tmp/seed-{tag}/src/main.rs; \
             chown -R 65534:65534 /tmp/seed-{tag}; \
             mkfs.ext4 -q -d /tmp/seed-{tag} {img} 64M; sha256sum {img}"
        ),
    );
    if !seed.ok() {
        return Err(format!("seed: {}", seed.text()));
    }
    // The guest's edits: copy, create, delete — then `sync` — then one write
    // left unsynced, so the SIGKILL case shows what an unclean end loses.
    let script = "set -e; ls -la /work; cat /work/seed.txt > /work/copied.txt; \
                  echo guest-edit > /work/edit.txt; rm /work/src/main.rs; sync; \
                  echo unsynced > /work/unsynced.txt; echo P4-DONE";
    let rootfs = bake_workload_rootfs(tag, script)?;
    let pod = create_pod(HOST, &pod_spec(tag, Some(&img), Some(&rootfs)))?;
    let done = wait_console_marker(HOST, &pod, "[workload] P4-DONE", Duration::from_secs(90));
    let result = match &done {
        Ok(d) => format!("guest edits done +{d:.1?} after create"),
        Err(e) => e.clone(),
    };
    if unclean {
        let k = sh(HOST, "pkill -9 -x firecracker; echo killed=$?");
        println!("{tag}: {}", k.text());
        std::thread::sleep(Duration::from_secs(2));
    }
    let (ccode, _) = cancel_pod(HOST, &pod);
    std::thread::sleep(Duration::from_secs(2));
    let harvest = sh(
        HOST,
        &format!(
            "e2fsck -fp {img}; echo e2fsck_exit=$?; \
             for f in seed.txt copied.txt edit.txt unsynced.txt src/main.rs; do \
               echo \"$f=$(debugfs -R \"cat /$f\" {img} 2>/dev/null | tr -d '\\n')\"; done"
        ),
    );
    let h = harvest.text();
    println!("{tag}: workload {result}\n{h}");
    if done.is_err() {
        return Err(format!(
            "workload never finished: {result}\n{}",
            pod_console_tail(HOST, &pod)
        ));
    }
    let edits = kv(&h, "copied.txt").as_deref() == Some(&format!("seeded-{tag}"))
        && kv(&h, "edit.txt").as_deref() == Some("guest-edit")
        && kv(&h, "src/main.rs").as_deref() == Some("");
    let summary = format!(
        "{} e2fsck={:?} copied+edit+delete visible={edits} unsynced={:?} cancel={ccode}",
        if unclean {
            "SIGKILL firecracker"
        } else {
            "clean cancel"
        },
        kv(&h, "e2fsck_exit"),
        kv(&h, "unsynced.txt"),
    );
    if edits { Ok(summary) } else { Err(summary) }
}

/// P6: repeated pod lifecycles; count and recover host deaths.
#[test]
#[ignore = "spike: boots 40+ pods under nested virtualization"]
fn p6_lifecycles() {
    if !enabled() {
        return;
    }
    let target: usize = std::env::var("NUCLEUS_SPIKE_LIFECYCLES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(40);
    ensure_volume();
    if host_state(HOST).expect("observe spike host state") != "running" {
        remove(HOST);
        let run = run_host(&HostOpts::node(HOST));
        assert!(run.ok(), "run: {}", run.text());
    }
    wait_node_healthy(HOST, Duration::from_secs(120)).expect("node healthy");
    let marker = sh(HOST, "sha256sum /srv/state/ca/ca-cert.pem");
    assert!(
        marker.ok() && !marker.stdout.trim().is_empty(),
        "read CA digest"
    );
    let marker = marker.stdout;
    // NUCLEUS_SPIKE_P6_LOAD=1: each pod runs ~10 s of guest CPU + block I/O
    // before it is cancelled, so the nested guest takes the exits a real
    // workload does. An idle pod exits the VM far less than a gate build
    // (#3010's workload), and the crash is on the nested exit path.
    //   exec — ~4.5k fork+exec/s for 10 s. (Recorded verbatim: the `dd`
    //          target is not writable by the workload uid, so every round is
    //          a process spawn that fails fast — syscall/page-fault heavy, no
    //          block I/O. `rounds` on the console counts spawns.)
    //   io   — 16 MiB `dd ... conv=fsync` rounds onto a scratch disk for 10 s:
    //          virtio-blk MMIO exits and interrupts.
    let load = std::env::var("NUCLEUS_SPIKE_P6_LOAD").ok();
    let (rootfs, scratch) = match load.as_deref() {
        Some("exec") => (
            Some(
                bake_workload_rootfs(
                    "p6-exec",
                    "end=$(( $(date +%s) + 10 )); n=0; while [ $(date +%s) -lt $end ]; do \
                     dd if=/dev/urandom of=/var/tmp/p6.bin bs=1M count=16 conv=fsync 2>/dev/null; \
                     n=$((n+1)); done; rm -f /var/tmp/p6.bin; echo P6-DONE rounds=$n",
                )
                .expect("bake P6 exec rootfs"),
            ),
            None,
        ),
        Some("io") => {
            let seed = sh(
                HOST,
                "set -e; rm -rf /tmp/p6-seed /srv/work/p6-io.ext4; mkdir -p /tmp/p6-seed /srv/work; \
                 chown 65534:65534 /tmp/p6-seed; mkfs.ext4 -q -d /tmp/p6-seed /srv/work/p6-io.ext4 256M",
            );
            assert!(seed.ok(), "seed p6 scratch: {}", seed.text());
            (
                Some(
                    bake_workload_rootfs(
                        "p6-io",
                        "end=$(( $(date +%s) + 10 )); n=0; f=0; while [ $(date +%s) -lt $end ]; do \
                         if dd if=/dev/urandom of=/work/p6.bin bs=1M count=16 conv=fsync 2>/dev/null; \
                         then n=$((n+1)); else f=$((f+1)); fi; done; rm -f /work/p6.bin; \
                         echo P6-DONE rounds=$n failed=$f",
                    )
                    .expect("bake P6 io rootfs"),
                ),
                Some("/srv/work/p6-io.ext4".to_string()),
            )
        }
        _ => (None, None),
    };
    let load = rootfs.is_some();

    let mut completed = 0usize;
    let mut since_death = 0usize;
    let mut deaths: Vec<String> = Vec::new();
    let mut boot_times = Vec::new();
    let mut attempts = 0usize;
    while completed < target && attempts < target * 2 {
        attempts += 1;
        let last_ok = Instant::now();
        let outcome = (|| {
            let pod = create_pod(
                HOST,
                &pod_spec(
                    &format!("p6-{attempts}"),
                    scratch.as_deref(),
                    rootfs.as_deref(),
                ),
            )?;
            let (d, _) = wait_proxy_healthy(HOST, &pod, Duration::from_secs(60))?;
            if load {
                let w = wait_console_marker(
                    HOST,
                    &pod,
                    "[workload] P6-DONE",
                    Duration::from_secs(180),
                )?;
                println!("  load finished +{w:.1?}");
            }
            let (c, b) = cancel_pod(HOST, &pod);
            if c != 200 {
                return Err(format!("cancel {c}: {b}"));
            }
            Ok(pod.create + d)
        })();
        match outcome {
            Ok(d) => {
                completed += 1;
                since_death += 1;
                boot_times.push(d);
                println!("lifecycle {completed}/{target}: pod healthy in {d:.1?}");
            }
            Err(e) => {
                // Did the host VM die, or did one pod fail?
                let detect_started = Instant::now();
                let mut state = host_state(HOST).expect("observe spike host state");
                while state == "running" && detect_started.elapsed() < Duration::from_secs(10) {
                    std::thread::sleep(Duration::from_millis(250));
                    state = host_state(HOST).expect("observe spike host state");
                }
                let detected = detect_started.elapsed();
                if state == "running" {
                    println!("attempt {attempts}: pod failure, host still running: {e}");
                    continue;
                }
                let list_json = container(&["list", "--all", "--format", "json"]).stdout;
                let boot_log = container(&["logs", "--boot", HOST]).text();
                let boot_tail: Vec<&str> = boot_log.lines().rev().take(8).collect();
                let restart_started = Instant::now();
                let start = container(&["start", HOST]);
                let healthy = wait_node_healthy(HOST, Duration::from_secs(120));
                let restart = restart_started.elapsed();
                let marker_after = sh(HOST, "sha256sum /srv/state/ca/ca-cert.pem").stdout;
                let d = format!(
                    "death after {since_death} lifecycles (attempt {attempts}): state={state}, \
                     detected {detected:.1?} after failure ({:.1?} after last op started), \
                     start ok={}, restart-to-healthy {restart:.1?} ok={}, volume intact={}; \
                     error: {}; list entry: {}; boot log tail: {}",
                    last_ok.elapsed(),
                    start.ok(),
                    healthy.is_ok(),
                    marker == marker_after,
                    e.lines().next().unwrap_or(""),
                    list_json.chars().take(400).collect::<String>(),
                    boot_tail.into_iter().rev().collect::<Vec<_>>().join(" / "),
                );
                println!("{d}");
                deaths.push(d);
                since_death = 0;
                if healthy.is_err() {
                    break;
                }
            }
        }
    }
    let mean = boot_times.iter().sum::<Duration>() / boot_times.len().max(1) as u32;
    row(
        "P6",
        if completed == target { "DONE" } else { "SHORT" },
        &format!(
            "{completed}/{target} lifecycles in {attempts} attempts, {} host deaths, mean create->healthy {mean:.1?}",
            deaths.len()
        ),
    );
    for d in &deaths {
        println!("  {d}");
    }
}

/// P6 (recovery half): kill the host VM with a pod running — the stand-in for
/// a nested-virtualization crash when none occurs on its own — and measure
/// what PR4's supervisor would see: detection latency from `container list`,
/// whether `container start` recovers, restart-to-healthy, volume intact, and
/// whether the node can boot a pod again over the dead pod's leftovers.
#[test]
#[ignore = "spike: kills and restarts the spike host"]
fn p6b_forced_death() {
    if !enabled() {
        return;
    }
    ensure_host();
    let marker = sh(HOST, "sha256sum /srv/state/ca/ca-cert.pem");
    assert!(
        marker.ok() && !marker.stdout.trim().is_empty(),
        "read CA digest"
    );
    let marker = marker.stdout;
    let pod = create_pod(HOST, &pod_spec("p6b", None, None)).expect("pod");
    wait_proxy_healthy(HOST, &pod, Duration::from_secs(60)).expect("pod healthy");

    // Poll the state the way a supervisor would, from a separate thread, so
    // the detection clock starts at the kill, not after it returns.
    let killed_at = Instant::now();
    let watcher = std::thread::spawn(move || {
        loop {
            let state = host_state(HOST).expect("observe spike host state");
            if state != "running" || killed_at.elapsed() > Duration::from_secs(60) {
                return (killed_at.elapsed(), state);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
    let kill = container(&["kill", "--signal", "KILL", HOST]);
    let (detected, state) = watcher.join().expect("watcher");
    println!(
        "kill ok={} ({:.1?}); list reported {state:?} after {detected:.2?}",
        kill.ok(),
        kill.elapsed
    );
    let list = container(&["list", "--all", "--format", "json"]).stdout;
    let entry = list
        .find(&format!("\"id\":\"{HOST}\""))
        .map(|i| list[i.saturating_sub(10)..(i + 120).min(list.len())].to_string())
        .unwrap_or_default();
    println!("list after death: …{entry}…");

    let restart_started = Instant::now();
    let start = container(&["start", HOST]);
    let healthy = wait_node_healthy(HOST, Duration::from_secs(120));
    let restart = restart_started.elapsed();
    let intact = sh(HOST, "sha256sum /srv/state/ca/ca-cert.pem").stdout == marker;
    let leftovers = sh(
        HOST,
        "ls /srv/jailer/firecracker 2>/dev/null | wc -l; ip netns list | wc -l",
    )
    .text()
    .replace('\n', " ");
    let again = create_pod(HOST, &pod_spec("p6b-after", None, None)).and_then(|p| {
        let r = wait_proxy_healthy(HOST, &p, Duration::from_secs(60));
        let _ = cancel_pod(HOST, &p);
        r.map(|(d, _)| p.create + d)
    });
    let ok = kill.ok()
        && state == "stopped"
        && detected < Duration::from_secs(5)
        && start.ok()
        && healthy.is_ok()
        && restart < Duration::from_secs(60)
        && intact
        && again.is_ok();
    row(
        "P6b",
        if ok { "PASS" } else { "FAIL" },
        &format!(
            "detected {detected:.2?} ({state}); `container start` ok={} restart-to-healthy {restart:.1?}; \
             volume intact={intact}; jail dirs + netns after restart: {leftovers}; next pod: {again:?}",
            start.ok()
        ),
    );
}

/// Remove every container this spike creates, and its volume.
#[test]
#[ignore = "spike: cleanup"]
fn cleanup() {
    if !enabled() {
        return;
    }
    let list = container(&["list", "--all", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_str(&list.stdout).unwrap_or_default();
    for c in v.as_array().into_iter().flatten() {
        let id = c
            .pointer("/configuration/id")
            .or_else(|| c.get("id"))
            .and_then(|x| x.as_str())
            .unwrap_or("");
        if id.starts_with(PREFIX) {
            println!("removing {id}");
            remove(id);
        }
    }
    let _ = container(&["volume", "delete", VOLUME]);
}
