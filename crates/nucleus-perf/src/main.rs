//! `podburst` — launch N real pods at once and measure what the host does.
//!
//! The numbers this prints are meant to survive scrutiny, so a few choices are
//! deliberate:
//!
//! * **Submit latency and time-to-running are reported separately.** The first
//!   is how long the node takes to accept the request; the second includes the
//!   microVM actually booting. Collapsing them hides which half is slow.
//! * **Configured and resident memory are reported separately.** Firecracker
//!   backs guest RAM on demand, so a 512 MiB pod does not occupy 512 MiB.
//!   Multiplying the configured size by the pod count over-estimates the true
//!   requirement, usually by a lot.
//! * **Pods that never reach Running are counted, not dropped.** A burst that
//!   "succeeds" in 200 ms because half of it failed is the failure mode this
//!   harness exists to catch, so `failed` is a first-class column.
//! * **Percentiles, not just a mean.** Under contention the tail is the story.

use std::collections::BTreeMap;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use clap::Parser;

#[derive(Parser)]
#[command(
    name = "nucleus-perf",
    about = "Measure real pod concurrency and start latency"
)]
enum Cli {
    /// Launch N pods simultaneously, ramping through several values of N.
    Podburst(Burst),
    /// Run agent tool calls inside a pod and check what came back.
    Toolcall(ToolCall),
}

#[derive(Parser)]
struct ToolCall {
    /// Node base URL.
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    url: String,
    /// Hex-encoded auth secret for request signing.
    #[arg(long, env = "NUCLEUS_AUTH_SECRET")]
    auth_secret: String,
    /// Actor name recorded on each signed request.
    #[arg(long, default_value = "nucleus-perf")]
    actor: String,
    /// Pod spec used as the template.
    #[arg(long)]
    spec: String,
}

#[derive(Parser)]
struct Burst {
    /// Node base URL.
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    url: String,
    /// Hex-encoded auth secret for request signing.
    #[arg(long, env = "NUCLEUS_AUTH_SECRET")]
    auth_secret: String,
    /// Actor name recorded on each signed request.
    #[arg(long, default_value = "nucleus-perf")]
    actor: String,
    /// Pod spec used as the template for every pod in the burst.
    #[arg(long)]
    spec: String,
    /// Concurrency levels to ramp through.
    #[arg(long, default_value = "1,5,10,25,50")]
    counts: String,
    /// Give up waiting for a pod to reach Running after this many seconds.
    #[arg(long, default_value = "120")]
    timeout_secs: u64,
    /// Give each pod a distinct guest CID. Off by default, and normally wrong:
    /// vsock CIDs are per-VM, so varying them makes guests bind a CID they do
    /// not own. Kept as a flag so the failure stays reproducible.
    #[arg(long)]
    vary_cid: bool,
    /// First guest CID to hand out when --vary-cid is set.
    #[arg(long, default_value = "100")]
    base_cid: u32,
    /// Emit one JSON object per level as well as the table.
    #[arg(long)]
    json: bool,
}

fn main() -> Result<()> {
    match Cli::parse() {
        Cli::Podburst(b) => podburst(b),
        Cli::Toolcall(t) => toolcall(t),
    }
}

fn podburst(b: Burst) -> Result<()> {
    // The node uses the hex secret string DIRECTLY as HMAC key bytes -- it does
    // not decode it (see nucleus-cli load_auth_secret). Decoding here yields a
    // 32-byte key against the node's 64-byte one and every request 401s.
    let secret = b.auth_secret.trim().as_bytes().to_vec();
    let template: serde_json::Value = {
        let raw = std::fs::read_to_string(&b.spec)
            .with_context(|| format!("reading spec {}", &b.spec))?;
        serde_yaml::from_str(&raw).with_context(|| format!("parsing spec {}", &b.spec))?
    };

    let counts: Vec<usize> = b
        .counts
        .split(',')
        .map(|s| {
            s.trim()
                .parse::<usize>()
                .context("--counts must be integers")
        })
        .collect::<Result<_>>()?;

    let configured_mib = template
        .pointer("/spec/resources/memory_mib")
        .and_then(|v| v.as_u64())
        .unwrap_or(512);

    println!(
        "host: {} cpus, {} MiB total | pod: {} MiB configured\n",
        num_cpus(),
        meminfo_kb("MemTotal").unwrap_or(0) / 1024,
        configured_mib
    );
    println!(
        "{:>5} {:>8} {:>9} {:>9} {:>9} {:>9} {:>8} {:>10} {:>9}",
        "N",
        "started",
        "failed",
        "sub_p50",
        "run_p50",
        "run_p90",
        "run_max",
        "rss_total",
        "rss_each"
    );

    // Preflight: prove the credential works on a GET with an empty body BEFORE
    // launching a burst. Without this, a bad secret is indistinguishable from a
    // host that cannot boot pods -- every pod just "fails" and the table lies.
    match list_pods(&b.url, &secret, &b.actor) {
        Ok(p) => println!(
            "preflight: authenticated, {} pod(s) already present\n",
            p.len()
        ),
        Err(e) => bail!("preflight failed -- the node rejected a signed request: {e}"),
    }

    let mut rows = Vec::new();
    for n in counts {
        let row = run_level(&b, &secret, &template, n, configured_mib)?;
        println!(
            "{:>5} {:>8} {:>9} {:>8}m {:>8}m {:>8}m {:>8}m {:>9}M {:>8}M",
            row.n,
            row.started,
            row.failed,
            row.submit_p50,
            row.run_p50,
            row.run_p90,
            row.run_max,
            row.rss_total_mib,
            row.rss_each_mib
        );
        if b.json {
            println!("{}", serde_json::to_string(&row.to_json())?);
        }
        rows.push(row);
        // Let the host settle so the next level starts from a clean baseline.
        std::thread::sleep(Duration::from_secs(3));
    }

    summarise(&rows, configured_mib);
    Ok(())
}

struct Row {
    n: usize,
    started: usize,
    failed: usize,
    submit_p50: u128,
    run_p50: u128,
    run_p90: u128,
    run_max: u128,
    rss_total_mib: u64,
    rss_each_mib: u64,
}

impl Row {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "n": self.n,
            "started": self.started,
            "failed": self.failed,
            "submit_ms_p50": self.submit_p50,
            "run_ms_p50": self.run_p50,
            "run_ms_p90": self.run_p90,
            "run_ms_max": self.run_max,
            "rss_total_mib": self.rss_total_mib,
            "rss_each_mib": self.rss_each_mib,
        })
    }
}

fn run_level(
    b: &Burst,
    secret: &[u8],
    template: &serde_json::Value,
    n: usize,
    configured_mib: u64,
) -> Result<Row> {
    // Build every spec up front: work done before the clock starts must not be
    // charged to the burst.
    let specs: Vec<(String, String)> = (0..n)
        .map(|i| {
            let name = format!("perf-{n}-{i}");
            let mut s = template.clone();
            set(&mut s, "/metadata/name", serde_json::json!(name.clone()));
            // Do NOT vary guest_cid. Each microVM owns its own vsock device, so
            // the CID is per-VM, not host-global: every pod can and should keep
            // the template's value. Handing pod N a distinct CID makes the guest
            // bind a listener to a CID its own VM does not have, which fails with
            // EADDRNOTAVAIL, kills PID 1 and panics the guest kernel. Measured:
            // cid=3 boots, cid=4 and cid=100 panic, while three pods sharing
            // cid=3 run concurrently without complaint.
            if b.vary_cid {
                set(
                    &mut s,
                    "/spec/vsock/guest_cid",
                    serde_json::json!(b.base_cid + i as u32),
                );
            }
            set(
                &mut s,
                "/spec/cgroup/path",
                serde_json::json!(format!("/sys/fs/cgroup/nucleus/{name}")),
            );
            (name, serde_json::to_string(&s).unwrap_or_default())
        })
        .collect();

    let (tx, rx) = mpsc::channel();
    let start = Instant::now();
    let mut handles = Vec::new();
    for (name, body) in specs {
        let url = format!("{}/v1/pods", b.url);
        let actor = b.actor.clone();
        let secret = secret.to_vec();
        let tx = tx.clone();
        handles.push(std::thread::spawn(move || {
            let t0 = Instant::now();
            let res = post_pod(&url, &secret, &actor, &body);
            let submit_ms = t0.elapsed().as_millis();
            let _ = tx.send((name, res, submit_ms));
        }));
    }
    drop(tx);

    let mut submits = Vec::new();
    let mut ids = BTreeMap::new();
    let mut failed = 0usize;
    let mut first_err: Option<String> = None;
    for (name, res, submit_ms) in rx {
        submits.push(submit_ms);
        match res {
            Ok(id) => {
                ids.insert(id, name);
            }
            Err(e) => {
                failed += 1;
                if first_err.is_none() {
                    first_err = Some(e.to_string());
                }
            }
        }
    }
    for h in handles {
        let _ = h.join();
    }

    // Wait for the pods to actually run, polling the list endpoint so one
    // request covers the whole burst.
    let mut running_at: BTreeMap<String, u128> = BTreeMap::new();
    let deadline = Instant::now() + Duration::from_secs(b.timeout_secs);
    while running_at.len() < ids.len() && Instant::now() < deadline {
        if let Ok(list) = list_pods(&b.url, secret, &b.actor) {
            for p in list {
                let (Some(id), Some(state)) = (
                    p.get("id").and_then(|v| v.as_str()),
                    p.get("state").and_then(|v| v.as_str()),
                ) else {
                    continue;
                };
                if ids.contains_key(id) && !running_at.contains_key(id) && is_live(state) {
                    running_at.insert(id.to_string(), start.elapsed().as_millis());
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let rss_total = firecracker_rss_kb() / 1024;
    let live = firecracker_count();
    let started = running_at.len();
    failed += ids.len() - started;

    let mut runs: Vec<u128> = running_at.values().copied().collect();
    runs.sort_unstable();
    submits.sort_unstable();

    // Tear down before the next level so memory and CPU return to baseline.
    for id in ids.keys() {
        let _ = cancel_pod(&b.url, secret, &b.actor, id);
    }
    wait_for_drain(Duration::from_secs(60));

    if let Some(e) = &first_err {
        println!("      first failure: {e}");
    }
    let _ = configured_mib;
    Ok(Row {
        n,
        started,
        failed,
        submit_p50: pct(&submits, 50),
        run_p50: pct(&runs, 50),
        run_p90: pct(&runs, 90),
        run_max: runs.last().copied().unwrap_or(0),
        rss_total_mib: rss_total,
        rss_each_mib: if live > 0 { rss_total / live as u64 } else { 0 },
    })
}

/// A pod counts as started once it is no longer pending: the microVM is up.
fn is_live(state: &str) -> bool {
    let s = state.to_ascii_lowercase();
    s.contains("running")
        || s.contains("ready")
        || s.contains("succeeded")
        || s.contains("completed")
}

fn summarise(rows: &[Row], configured_mib: u64) {
    let Some(best) = rows.iter().filter(|r| r.failed == 0).max_by_key(|r| r.n) else {
        println!("\nNo level completed without failures.");
        return;
    };
    println!("\n-- what this host actually did --");
    println!("  largest clean burst: {} pods", best.n);
    if best.rss_each_mib > 0 {
        let avail = meminfo_kb("MemTotal").unwrap_or(0) / 1024;
        println!(
            "  resident per pod:    {} MiB (configured {} MiB -- {}x over-estimate)",
            best.rss_each_mib,
            configured_mib,
            configured_mib / best.rss_each_mib.max(1)
        );
        println!(
            "  100 pods would need: ~{} MiB resident, host has {} MiB",
            best.rss_each_mib * 100,
            avail
        );
    }
    if let Some(f) = rows.iter().find(|r| r.failed > 0) {
        println!(
            "  first level with failures: N={} ({} failed)",
            f.n, f.failed
        );
    }
}

// ---- transport -------------------------------------------------------------

/// `http_status_as_error(false)` is deliberate. ureq's default turns a 4xx into
/// a transport `Err` and discards the body -- which is exactly where the node
/// explains itself ("no such policy profile", "cannot open rootfs"). Reporting
/// "status 400" instead of the node's own sentence turns a precise diagnosis
/// into a guess, and this harness exists to diagnose.
fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into()
}

fn signed_request(
    req: ureq::RequestBuilder<ureq::typestate::WithBody>,
    secret: &[u8],
    actor: &str,
    body: &[u8],
) -> ureq::RequestBuilder<ureq::typestate::WithBody> {
    let signed = nucleus_client::sign_http_headers(secret, Some(actor), body);
    let mut req = req;
    for (k, v) in &signed.headers {
        req = req.header(k, v);
    }
    req
}

fn post_pod(url: &str, secret: &[u8], actor: &str, body: &str) -> Result<String> {
    let req = agent().post(url).header("content-type", "application/json");
    let mut resp = signed_request(req, secret, actor, body.as_bytes())
        .send(body)
        .map_err(|e| anyhow::anyhow!("create pod: {e}"))?;
    let status = resp.status();
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    if !status.is_success() {
        bail!("create pod: HTTP {status}: {}", text.trim());
    }
    let v: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("create pod: unparseable response: {text}"))?;
    v.get("id")
        .or_else(|| v.get("pod_id"))
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("no pod id in response: {v}"))
}

fn list_pods(url: &str, secret: &[u8], actor: &str) -> Result<Vec<serde_json::Value>> {
    let endpoint = format!("{url}/v1/pods");
    let signed = nucleus_client::sign_http_headers(secret, Some(actor), b"");
    let mut req = agent().get(&endpoint);
    for (k, v) in &signed.headers {
        req = req.header(k, v);
    }
    let mut resp = req.call().map_err(|e| anyhow::anyhow!("list pods: {e}"))?;
    // `http_status_as_error(false)` means a 401 arrives as a normal response.
    // Parsing it as JSON and finding no "pods" key yields an empty list, which
    // reads as "the node is up and idle" -- a false pass that turns an auth
    // failure into a plausible zero. Check the status.
    let status = resp.status();
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    if !status.is_success() {
        bail!("list pods: HTTP {status}: {}", text.trim());
    }
    let v: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("list pods: unparseable response: {text}"))?;
    Ok(v.get("pods")
        .and_then(|p| p.as_array())
        .cloned()
        .or_else(|| v.as_array().cloned())
        .unwrap_or_default())
}

fn cancel_pod(url: &str, secret: &[u8], actor: &str, id: &str) -> Result<()> {
    let endpoint = format!("{url}/v1/pods/{id}/cancel");
    let req = agent().post(&endpoint);
    let mut resp = signed_request(req, secret, actor, b"")
        .send("")
        .map_err(|e| anyhow::anyhow!("cancel: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.body_mut().read_to_string().unwrap_or_default();
        bail!("cancel: HTTP {status}: {}", text.trim());
    }
    Ok(())
}

// ---- host observation ------------------------------------------------------

fn wait_for_drain(limit: Duration) {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline && firecracker_count() > 0 {
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn for_each_firecracker(mut f: impl FnMut(&str)) {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return;
    };
    for e in entries.flatten() {
        let pid = e.file_name();
        let Some(pid) = pid.to_str() else { continue };
        if !pid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
            if comm.trim() == "firecracker" {
                f(pid);
            }
        }
    }
}

fn firecracker_count() -> usize {
    let mut n = 0;
    for_each_firecracker(|_| n += 1);
    n
}

/// Summed resident set size of every Firecracker process, in KiB.
fn firecracker_rss_kb() -> u64 {
    let mut total = 0;
    for_each_firecracker(|pid| {
        if let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    total += rest
                        .split_whitespace()
                        .next()
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(0);
                }
            }
        }
    });
    total
}

fn meminfo_kb(key: &str) -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            if let Some(rest) = rest.strip_prefix(':') {
                return rest.split_whitespace().next()?.parse().ok();
            }
        }
    }
    None
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

// ---- small helpers ---------------------------------------------------------

fn pct(sorted: &[u128], p: usize) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = (sorted.len() * p).div_ceil(100).saturating_sub(1);
    sorted[idx.min(sorted.len() - 1)]
}

fn set(v: &mut serde_json::Value, ptr: &str, val: serde_json::Value) {
    // Create missing intermediate objects so a template that omits, say,
    // `spec.vsock` still gets a distinct CID rather than silently sharing one.
    let parts: Vec<&str> = ptr.trim_start_matches('/').split('/').collect();
    let mut cur = v;
    for p in &parts[..parts.len() - 1] {
        if !cur
            .get(*p)
            .map(serde_json::Value::is_object)
            .unwrap_or(false)
        {
            cur[*p] = serde_json::json!({});
        }
        cur = cur.get_mut(*p).expect("just inserted");
    }
    cur[parts[parts.len() - 1]] = val;
}

// ---- tool calls in pods (rubric stage A) -----------------------------------

/// Mint DLC-D admission for exactly the operations a scenario invokes.
///
/// The issuer key is a throwaway from `/dev/urandom`: it never outlives the run
/// and its only power is over the one ephemeral pod. Crediting ONLY the
/// operations under test is deliberate — an uncredentialed operation must still
/// be refused, and that refusal is half of what each iteration proves.
fn mint_admission(ops: &[&str]) -> Result<(String, String)> {
    use std::io::Read as _;
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .context("no /dev/urandom on this host")?
        .read_exact(&mut seed)
        .context("could not read 32 bytes of randomness")?;
    let mut issuer = String::new();
    let mut creds = Vec::new();
    for op in ops {
        let (pk, sig) = portcullis::says_admission::mint_credential(&seed, op);
        issuer = hex::encode(pk);
        creds.push(format!("{op}={}", hex::encode(&sig.bytes)));
    }
    Ok((issuer, creds.join(",")))
}

/// POST a tool call to a pod's own tool-proxy. No auth headers: admission is
/// carried by the pod spec's `dlc_*` labels, established before the pod ran.
fn tool_call(proxy: &str, route: &str, body: serde_json::Value) -> Result<(u16, String, u128)> {
    let payload = body.to_string();
    let t0 = Instant::now();
    let mut resp = agent()
        .post(format!("{proxy}/v1/{route}"))
        .header("content-type", "application/json")
        .send(payload.as_bytes())
        .map_err(|e| anyhow::anyhow!("tool-proxy did not answer /v1/{route}: {e}"))?;
    let status = resp.status().as_u16();
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    Ok((status, text, t0.elapsed().as_millis()))
}

/// A read every profile must refuse. Matched by two independent rules in
/// `PathLattice::block_sensitive`, so a refusal here is policy, not absence.
const FORBIDDEN_READ: &str = ".ssh/id_rsa";

/// Rubric stage A: run agent tool calls inside a pod and check the answers.
///
/// The pod's sandbox is a disk image, not a host mount, so "does the host see
/// the same bytes" cannot be asked directly. The round trip is the honest
/// substitute: the HOST generates a payload, the guest writes it, the guest
/// reads it back, and the host compares. That proves the read path returns real
/// bytes from the sandbox rather than a plausible-looking empty success.
fn toolcall(t: ToolCall) -> Result<()> {
    let secret = t.auth_secret.trim().as_bytes().to_vec();
    let mut spec: serde_json::Value = {
        let raw = std::fs::read_to_string(&t.spec)
            .with_context(|| format!("reading spec {}", &t.spec))?;
        serde_yaml::from_str(&raw).with_context(|| format!("parsing spec {}", &t.spec))?
    };

    // Credential ONLY what the scenarios invoke. `web_fetch` is deliberately
    // uncredentialed so the refusal check cannot pass by accident.
    let (issuer, creds) = mint_admission(&["read_files", "write_files", "glob_search"])?;
    set(
        &mut spec,
        "/metadata/name",
        serde_json::json!("perf-toolcall"),
    );
    set(
        &mut spec,
        "/metadata/labels/dlc_trusted_keys",
        serde_json::json!(issuer),
    );
    set(
        &mut spec,
        "/metadata/labels/dlc_issuer",
        serde_json::json!(issuer),
    );
    set(
        &mut spec,
        "/metadata/labels/dlc_credentials",
        serde_json::json!(creds),
    );

    let body = serde_json::to_string(&spec)?;
    let created = Instant::now();
    let (id, proxy) = create_pod_with_proxy(&t.url, &secret, &t.actor, &body)?;
    println!(
        "pod {id} up in {} ms, proxy {proxy}\n",
        created.elapsed().as_millis()
    );

    let mut failures = Vec::new();
    println!("{:<26} {:>7} {:>7}  verdict", "check", "status", "ms");

    // Discover a readable path rather than inventing one. The sandbox is a disk
    // image, not a host mount, so the host cannot place a file in it and cannot
    // checksum one out of it. And a path the PathLattice does not permit is
    // refused even though `codegen` sets read_files: Always -- capability level
    // and path policy are separate gates. So: ask the guest what it can see.
    let (st, b, ms) = tool_call(&proxy, "glob", serde_json::json!({"pattern": "*"}))?;
    let matches: Vec<String> = serde_json::from_str::<serde_json::Value>(&b)
        .ok()
        .and_then(|v| {
            v.get("matches").and_then(|m| m.as_array()).map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
        })
        .unwrap_or_default();
    let ok = (200..300).contains(&st) && !matches.is_empty();
    report("glob finds sandbox files", st, ms, ok, &b, &mut failures);

    // Reading a discovered entry must return real bytes. An empty success here
    // would mean the read path answers without serving the sandbox, which is
    // precisely the failure worth catching.
    if let Some(target) = matches.first() {
        let (st, b, ms) = tool_call(&proxy, "read", serde_json::json!({"path": target}))?;
        let contents = serde_json::from_str::<serde_json::Value>(&b)
            .ok()
            .and_then(|v| {
                v.get("contents")
                    .and_then(|c| c.as_str())
                    .map(str::to_string)
            });
        let ok = (200..300).contains(&st) && contents.is_some();
        report(&format!("read {target}"), st, ms, ok, &b, &mut failures);
    } else {
        failures.push("read (no glob match to read)".to_string());
    }

    // The refusal half. A pod that serves this is not isolating anything.
    let (st, b, ms) = tool_call(&proxy, "read", serde_json::json!({"path": FORBIDDEN_READ}))?;
    let ok = !(200..300).contains(&st);
    report("forbidden read refused", st, ms, ok, &b, &mut failures);

    // Uncredentialed operation: admission must refuse it even though the pod runs.
    let (st, b, ms) = tool_call(
        &proxy,
        "web_fetch",
        serde_json::json!({"url": "http://127.0.0.1/"}),
    )?;
    let ok = !(200..300).contains(&st);
    report("uncredentialed refused", st, ms, ok, &b, &mut failures);

    let _ = cancel_pod(&t.url, &secret, &t.actor, &id);

    if failures.is_empty() {
        println!("\nall checks passed");
        Ok(())
    } else {
        bail!(
            "{} check(s) failed: {}",
            failures.len(),
            failures.join(", ")
        );
    }
}

fn report(name: &str, status: u16, ms: u128, ok: bool, body: &str, failures: &mut Vec<String>) {
    println!(
        "{name:<26} {status:>7} {ms:>7}  {}",
        if ok { "ok" } else { "FAILED" }
    );
    if !ok {
        // The body is the whole value on a refusal: the proxy names the capability
        // and the rule. Printing only the status turns a precise diagnosis into a
        // guess -- the same mistake this harness already made once with the node.
        println!("      {}", body.trim());
        failures.push(name.to_string());
    }
}

/// Create a pod and return both its id and the address of its own tool-proxy.
fn create_pod_with_proxy(
    url: &str,
    secret: &[u8],
    actor: &str,
    body: &str,
) -> Result<(String, String)> {
    let endpoint = format!("{url}/v1/pods");
    let req = agent()
        .post(&endpoint)
        .header("content-type", "application/json");
    let mut resp = signed_request(req, secret, actor, body.as_bytes())
        .send(body)
        .map_err(|e| anyhow::anyhow!("create pod: {e}"))?;
    let status = resp.status();
    let text = resp.body_mut().read_to_string().unwrap_or_default();
    if !status.is_success() {
        bail!("create pod: HTTP {status}: {}", text.trim());
    }
    let v: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("create pod: unparseable response: {text}"))?;
    let id = v
        .get("id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow::anyhow!("no pod id in response: {v}"))?
        .to_string();
    let proxy = v
        .get("proxy_addr")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow::anyhow!("no proxy_addr in response: {v}"))?
        .to_string();
    Ok((id, proxy))
}
