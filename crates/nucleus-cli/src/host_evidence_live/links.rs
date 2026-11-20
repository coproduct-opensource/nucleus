//! ADR 0017's gauntlet: links between pods on a real Firecracker node.
//! Live: Linux, KVM, root. Invoked by `cargo xtask links-live`.
//!
//! # What runs
//!
//! One node, started with `--egress-proxy-bin` so every pod gets a link proxy
//! (L4b), booted from a rootfs whose workload is `nucleus-link-probe`. The
//! harness then runs seven items and writes one JSON report:
//!
//! - **(a) differential conformance.** N random link, unlink and cancel
//!   operations are applied to the in-process `nucleus_ifc_kernel::links::LinkTable`
//!   (held to `LinkTable.lean` by L3) and to the live node's API. Every outcome
//!   must match. This is what removes "the real node behaves like the model"
//!   from the proofs' trusted base, on the operations it covers.
//! - **(b) per-request decisions.** A sender pod sends over a link and to an
//!   unlinked port; the destination's report must hold every answered request
//!   and none of the refused ones, and nothing the sender was not answered for.
//! - **(c) adversary.** A pod with no link tries raw vsock, a forged link
//!   name, smuggling, pipelining, Upgrade, a non-TLS CONNECT, a foreign CA and
//!   the connection cap. None may reach the destination undecided.
//! - **(d) isolation.** An unknown pod at either end of a link request gets
//!   the same 404, and the two cases' timings are reported (not judged).
//! - **(e) chaos.** A linked pod's cancel is refused (409); its reaper timeout
//!   drops the link with a signed receipt; links and unlinks raced on one row
//!   leave the table consistent; an unlink mid-request; a node restart (whose
//!   result is recorded: the table is not persisted, which this records rather
//!   than hides).
//! - **(f) canary.** A pod nobody links receives nothing.
//! - **(g) receipts.** Every receipt the run collected verifies with the
//!   node's executor public key alone.
//!
//! # What it cannot cover
//!
//! The harness mints one CLI identity, in the node's own trust domain, so every
//! pod is in one domain (`""`, node-local). Links ACROSS trust domains need
//! pods with federated owners, which needs a second trust domain's CA enrolled
//! with the node's federation ingress. That is not minted here; the refusal is
//! covered by L4a's handler tests and `no_cross_tenant_link`, and (d) covers
//! the identical-404 half with unknown pods.

use super::node::Node;
use anyhow::{Context, Result, bail, ensure};
use nucleus_ifc_kernel::extracted::link::Link;
use nucleus_ifc_kernel::links::{LinkTable, Outcome, Scope};
use nucleus_link_probe::{AttemptOutcome, Event};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use uuid::Uuid;

// ------------------------------------------------------------------ report

/// One item's verdict. `Recorded` is a measurement the gauntlet reports but
/// does not judge; `Inconclusive` means the item could not observe enough.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Verdict {
    Pass,
    Fail,
    Inconclusive,
    Recorded,
}

#[derive(Debug, Serialize)]
pub(crate) struct Item {
    pub name: &'static str,
    pub verdict: Verdict,
    pub numbers: Value,
    pub notes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Report {
    pub items: Vec<Item>,
}

impl Report {
    /// Whether any item failed. Inconclusive and recorded items do not fail
    /// the run; they are visible in the report.
    pub fn failed(&self) -> bool {
        self.items.iter().any(|i| i.verdict == Verdict::Fail)
    }
}

// ------------------------------------------------------------ differential

/// What a caller observed for one operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum Observed {
    Done,
    Refused,
    NotFound,
    Other(u16),
}

pub(crate) fn observed(status: u16) -> Observed {
    match status {
        200 => Observed::Done,
        409 => Observed::Refused,
        404 => Observed::NotFound,
        s => Observed::Other(s),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum Op {
    Link { src: usize, dst: usize, port: u32 },
    Unlink { src: usize, dst: usize, port: u32 },
    Cancel { pod: usize },
}

/// What the node's API must answer for `op`, given the model's outcome. The
/// mapping is `pod_links.rs`'s: a refused link is 409, a refused unlink is 404
/// (an absent row reveals nothing), a refused cancel is 409.
pub(crate) fn expected(op: Op, model: Outcome) -> Observed {
    match (op, model) {
        (_, Outcome::Done) => Observed::Done,
        (Op::Unlink { .. }, Outcome::Refused) => Observed::NotFound,
        (Op::Link { .. } | Op::Cancel { .. }, Outcome::Refused) => Observed::Refused,
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct Step {
    pub index: usize,
    pub op: Op,
    pub model: Observed,
    pub node: Observed,
}

/// Every step where the node answered other than the model. Empty is a pass.
pub(crate) fn mismatches(steps: &[Step]) -> Vec<String> {
    steps
        .iter()
        .filter(|s| s.model != s.node)
        .map(|s| {
            format!(
                "op {} {:?}: model {:?}, node {:?}",
                s.index, s.op, s.model, s.node
            )
        })
        .collect()
}

/// A small deterministic generator, so a failing run is replayed by its seed.
pub(crate) struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// The operation mix: links and unlinks on a few ports, self links
/// included, cancels rare (each successful one boots a replacement).
pub(crate) fn gen_op(rng: &mut Rng, pods: usize) -> Op {
    const PORTS: [u32; 3] = [80, 81, 443];
    let src = rng.below(pods);
    let dst = rng.below(pods);
    let port = PORTS[rng.below(PORTS.len())];
    match rng.below(100) {
        0..=54 => Op::Link { src, dst, port },
        55..=96 => Op::Unlink { src, dst, port },
        _ => Op::Cancel { pod: src },
    }
}

/// Apply `op` to the model table over `slots`.
pub(crate) fn model_apply(table: &mut LinkTable, slots: &[Uuid], op: Op) -> Outcome {
    let id = |i: usize| slots[i].as_u128();
    match op {
        Op::Link { src, dst, port } => {
            table
                .link(
                    &Scope::NodeWide,
                    Link {
                        src: id(src),
                        dst: id(dst),
                        port,
                    },
                )
                .outcome
        }
        Op::Unlink { src, dst, port } => {
            table
                .unlink(
                    &Scope::NodeWide,
                    Link {
                        src: id(src),
                        dst: id(dst),
                        port,
                    },
                )
                .outcome
        }
        Op::Cancel { pod } => table.cancel(&Scope::NodeWide, id(pod)).outcome,
    }
}

/// Welch's t statistic for two samples (timings), reported, not judged.
pub(crate) fn welch_t(a: &[f64], b: &[f64]) -> Option<f64> {
    let stats = |x: &[f64]| {
        let n = x.len() as f64;
        let mean = x.iter().sum::<f64>() / n;
        let var = x.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1.0);
        (n, mean, var)
    };
    if a.len() < 2 || b.len() < 2 {
        return None;
    }
    let (na, ma, va) = stats(a);
    let (nb, mb, vb) = stats(b);
    let se = (va / na + vb / nb).sqrt();
    (se > 0.0).then(|| (ma - mb) / se)
}

// ---------------------------------------------------------------- the node

const PROBE: &str = "/usr/local/bin/nucleus-link-probe";

fn spec(name: &str, kernel: &Path, rootfs: &Path, timeout: u64, args: &[String]) -> Value {
    json!({
        "apiVersion": "nucleus/v1", "kind": "Pod",
        "metadata": {"name": name},
        "spec": {
            "work_dir": "/work", "timeout_seconds": timeout,
            "policy": {"type": "inline", "lattice": portcullis::PermissionLattice::permissive()},
            "image": {"kernel_path": kernel, "rootfs_path": rootfs, "read_only": true},
            "vsock": {"guest_cid": 3, "port": 5005},
            "workload": {"command": PROBE, "args": args}
        }
    })
}

/// The node's artifacts root: the kernel, and a fresh rootfs copy per pod
/// (the jailer hard-links each drive into its jail, as in `cross_pod`).
struct Artifacts {
    _dir: tempfile::TempDir,
    kernel: PathBuf,
    rootfs: PathBuf,
    root: PathBuf,
    next: usize,
}

impl Artifacts {
    fn stage(kernel: &Path, rootfs: &Path) -> Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::Builder::new()
            .prefix("lk")
            .disable_cleanup(std::env::var_os("NUCLEUS_LINKS_KEEP").is_some())
            .tempdir_in("/var/tmp")?;
        let root = dir.path().to_path_buf();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))?;
        let k = root.join("vmlinux");
        std::fs::copy(kernel, &k).context("copying the kernel")?;
        std::fs::set_permissions(&k, std::fs::Permissions::from_mode(0o644))?;
        Ok(Self {
            _dir: dir,
            kernel: k,
            rootfs: rootfs.to_path_buf(),
            root,
            next: 0,
        })
    }
    fn fresh_rootfs(&mut self) -> Result<PathBuf> {
        use std::os::unix::fs::PermissionsExt;
        self.next += 1;
        let to = self.root.join(format!("rootfs-{}.ext4", self.next));
        std::fs::copy(&self.rootfs, &to).context("copying the rootfs")?;
        std::fs::set_permissions(&to, std::fs::Permissions::from_mode(0o644))?;
        Ok(to)
    }
}

struct Run<'a> {
    node: &'a Node,
    art: &'a mut Artifacts,
    receipts: Vec<Value>,
}

impl Run<'_> {
    async fn create(&mut self, name: &str, timeout: u64, args: &[String]) -> Result<Uuid> {
        let rootfs = self.art.fresh_rootfs()?;
        let spec = spec(name, &self.art.kernel, &rootfs, timeout, args);
        let created: super::Created = serde_json::from_slice(
            &super::body(
                self.node
                    .client
                    .post(format!("{}/v1/pods", self.node.url))
                    .timeout(nucleus_spec::boot_budget::POD_CREATE_CLIENT_TIMEOUT)
                    .json(&spec)
                    .send()
                    .await?,
            )
            .await?,
        )?;
        Ok(created.id)
    }

    async fn state(&self, pod: Uuid) -> Result<Option<String>> {
        let bytes = super::body(
            self.node
                .client
                .get(format!("{}/v1/pods", self.node.url))
                .send()
                .await?,
        )
        .await?;
        let v: Value = serde_json::from_slice(&bytes)?;
        let list = v
            .as_array()
            .or_else(|| v.get("pods").and_then(Value::as_array))
            .context("pod listing shape")?;
        Ok(list
            .iter()
            .find(|p| p["id"].as_str() == Some(&pod.to_string()))
            .map(|p| {
                p["state"]
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| p["state"].to_string())
            }))
    }

    async fn wait_running(&self, pod: Uuid) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            if let Some(s) = self.state(pod).await? {
                if s.contains("running") {
                    return Ok(());
                }
                ensure!(
                    !s.contains("exited") && !s.contains("error"),
                    "pod {pod}: {s}"
                );
            }
            ensure!(Instant::now() < deadline, "pod {pod} never ran");
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// `(status, body)` of a link call; a 200's receipt is kept for (g).
    async fn link(&mut self, src: Uuid, dst: Uuid, port: u32) -> Result<(u16, String)> {
        let r = self
            .node
            .client
            .post(format!("{}/v1/pods/{src}/links", self.node.url))
            .json(&json!({"dst": dst, "port": port}))
            .send()
            .await?;
        self.keep(r).await
    }

    async fn unlink(&mut self, src: Uuid, dst: Uuid, port: u32) -> Result<(u16, String)> {
        let r = self
            .node
            .client
            .delete(format!(
                "{}/v1/pods/{src}/links/{dst}/{port}",
                self.node.url
            ))
            .send()
            .await?;
        self.keep(r).await
    }

    async fn cancel(&mut self, pod: Uuid) -> Result<u16> {
        let r = self
            .node
            .client
            .post(format!("{}/v1/pods/{pod}/cancel", self.node.url))
            .send()
            .await?;
        Ok(r.status().as_u16())
    }

    /// Unlink every row naming `pod`, then cancel it, so its vCPU is free for
    /// the next item. Found on the first local rehearsal (2026-11-19): items
    /// left their pods running, and the fifth item's create met "node capacity
    /// exhausted: 0 vCPUs" on a 12-vCPU host.
    async fn retire(&mut self, pod: Uuid) {
        if let Ok((_, v)) = self.listing(pod).await {
            for r in v["links"].as_array().cloned().unwrap_or_default() {
                if let (Some(s), Some(d), Some(port)) =
                    (r["src"].as_str(), r["dst"].as_str(), r["port"].as_u64())
                {
                    if let (Ok(s), Ok(d)) = (Uuid::parse_str(s), Uuid::parse_str(d)) {
                        let _ = self.unlink(s, d, port as u32).await;
                    }
                }
            }
        }
        let _ = self.cancel(pod).await;
    }

    async fn keep(&mut self, r: reqwest::Response) -> Result<(u16, String)> {
        let status = r.status().as_u16();
        let text = r.text().await?;
        if status == 200 {
            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                self.receipts.push(v);
            }
        }
        Ok((status, text))
    }

    async fn listing(&mut self, pod: Uuid) -> Result<(u16, Value)> {
        let r = self
            .node
            .client
            .get(format!("{}/v1/pods/{pod}/links", self.node.url))
            .send()
            .await?;
        let status = r.status().as_u16();
        let v: Value = r.json().await.unwrap_or(Value::Null);
        if let Some(d) = v["dropped"].as_array() {
            self.receipts.extend(d.iter().cloned());
        }
        Ok((status, v))
    }

    /// Everything `pod`'s probe reported so far: its console logs and, when
    /// served, its workload stdout. Deduplicated (the probe echoes to both
    /// streams).
    async fn events(&self, pod: Uuid) -> Vec<Event> {
        let mut text = String::new();
        let mut logs = Vec::new();
        console_logs(&self.node.state, pod, &mut logs);
        console_logs(self.node.jail_base(), pod, &mut logs);
        for l in logs {
            text.push_str(&String::from_utf8_lossy(
                &std::fs::read(l).unwrap_or_default(),
            ));
            text.push('\n');
        }
        if let Ok(r) = self
            .node
            .client
            .get(format!(
                "{}/v1/pods/{pod}/workload-logs/stdout",
                self.node.url
            ))
            .send()
            .await
        {
            if r.status().is_success() {
                text.push_str(&r.text().await.unwrap_or_default());
            }
        }
        let mut seen = BTreeSet::new();
        nucleus_link_probe::parse(&text)
            .into_iter()
            .filter(|e| seen.insert(serde_json::to_string(e).unwrap_or_default()))
            .collect()
    }

    async fn wait_done(&self, pod: Uuid, within: Duration) -> Vec<Event> {
        let deadline = Instant::now() + within;
        loop {
            let ev = self.events(pod).await;
            if ev.iter().any(|e| matches!(e, Event::Done { .. })) || Instant::now() > deadline {
                return ev;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Lines of `pod`'s host-effect authorization journal (ADR 0014).
    fn decisions(&self, pod: Uuid) -> String {
        let mut out = String::new();
        let mut found = Vec::new();
        named(
            &self.node.state,
            pod,
            nucleus_spec::host_effect::LOG_FILE,
            &mut found,
        );
        named(
            self.node.jail_base(),
            pod,
            nucleus_spec::host_effect::LOG_FILE,
            &mut found,
        );
        for f in found {
            out.push_str(&std::fs::read_to_string(f).unwrap_or_default());
        }
        out
    }
}

fn console_logs(root: &Path, pod: Uuid, out: &mut Vec<PathBuf>) {
    named(root, pod, "firecracker.log", out);
}

/// Every file called `file` under `root` whose path names `pod`.
fn named(root: &Path, pod: Uuid, file: &str, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            named(&path, pod, file, out);
        } else if path.file_name().is_some_and(|n| n == file)
            && path.to_string_lossy().contains(&pod.to_string())
        {
            out.push(path);
        }
    }
}

fn received(events: &[Event]) -> BTreeMap<String, u16> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::Received { id, port, .. } if !id.is_empty() => Some((id.clone(), *port)),
            _ => None,
        })
        .collect()
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

// ---------------------------------------------------------------- the items

async fn differential(run: &mut Run<'_>, pool: &mut [Uuid], ops: u64, seed: u64) -> Item {
    let mut table = LinkTable::empty();
    for p in pool.iter() {
        table.pod_started(p.as_u128(), String::new());
    }
    let mut rng = Rng::new(seed);
    let mut steps = Vec::new();
    let mut errors = Vec::new();
    let mut replaced = 0;
    for index in 0..ops as usize {
        let op = gen_op(&mut rng, pool.len());
        let model = model_apply(&mut table, pool, op);
        let node = match op {
            Op::Link { src, dst, port } => run.link(pool[src], pool[dst], port).await.map(|r| r.0),
            Op::Unlink { src, dst, port } => {
                run.unlink(pool[src], pool[dst], port).await.map(|r| r.0)
            }
            Op::Cancel { pod } => run.cancel(pool[pod]).await,
        };
        let node = match node {
            Ok(s) => observed(s),
            Err(e) => {
                errors.push(format!("op {index}: {e:#}"));
                break;
            }
        };
        let step = Step {
            index,
            op,
            model: expected(op, model),
            node,
        };
        steps.push(step);
        if step.model != step.node {
            break; // the first divergence is the finding; later steps would compound it
        }
        if let (Op::Cancel { pod }, Observed::Done) = (op, node) {
            match run
                .create("diff-replacement", 3600, &["serve".into(), "80".into()])
                .await
            {
                Ok(new) => {
                    if let Err(e) = run.wait_running(new).await {
                        errors.push(format!("replacement: {e:#}"));
                        break;
                    }
                    table.pod_started(new.as_u128(), String::new());
                    pool[pod] = new;
                    replaced += 1;
                }
                Err(e) => {
                    errors.push(format!("replacement: {e:#}"));
                    break;
                }
            }
        }
    }
    let bad = mismatches(&steps);
    let verdict = if !bad.is_empty() {
        Verdict::Fail
    } else if !errors.is_empty() {
        Verdict::Inconclusive
    } else {
        Verdict::Pass
    };
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    for s in &steps {
        *by_kind
            .entry(format!("{:?}->{:?}", std::mem::discriminant(&s.op), s.node))
            .or_default() += 1;
    }
    Item {
        name: "a_differential_conformance",
        verdict,
        numbers: json!({
            "ops_requested": ops, "ops_run": steps.len(), "seed": seed,
            "pods": pool.len(), "replacements": replaced,
            "done": steps.iter().filter(|s| s.node == Observed::Done).count(),
            "refused": steps.iter().filter(|s| s.node == Observed::Refused).count(),
            "not_found": steps.iter().filter(|s| s.node == Observed::NotFound).count(),
        }),
        notes: bad.into_iter().chain(errors).collect(),
    }
}

/// What item (b) counted. Found on the x86 gauntlet (2026-11-19): 63 of 200
/// linked requests were delivered and 137 ended 503, and the item still passed,
/// because a linked request that was neither delivered nor decided fell into no
/// bucket. `linked_failed` is that bucket.
struct PerRequestCounts {
    saw_anything: bool,
    /// Requests asked for, per kind.
    requested: u64,
    /// The fewest the sender reported sending, over the three kinds.
    sent_fewest: u64,
    linked_ok: u64,
    linked_failed: u64,
    linked_missing: u64,
    refused_leaked: u64,
    undecided: usize,
}

fn per_request_verdict(c: &PerRequestCounts) -> Verdict {
    if c.linked_failed + c.linked_missing + c.refused_leaked > 0 || c.undecided > 0 {
        Verdict::Fail
    } else if !c.saw_anything || c.linked_ok == 0 || c.sent_fewest < c.requested {
        Verdict::Inconclusive
    } else {
        Verdict::Pass
    }
}

/// Seconds the sender of `n` requests per kind is waited for.
fn sender_wait(n: u64) -> u64 {
    (n / 10).max(900)
}

async fn per_request(run: &mut Run<'_>, dst: Uuid, n: u64, seed: u64) -> Result<(Item, Uuid)> {
    let args: Vec<String> = [
        "send".into(),
        dst.to_string(),
        "8080".into(),
        n.to_string(),
        seed.to_string(),
        "--refused-port".into(),
        "8081".into(),
        "--tls".into(),
    ]
    .into();
    // About 20 requests per kind per second were measured on x86 (2026-11-20); allow
    // ten, so a large run is waited for rather than cut short at a fixed 900 s.
    let wait = Duration::from_secs(sender_wait(n));
    let src = run.create("sender", wait.as_secs() + 600, &args).await?;
    run.wait_running(src).await?;
    let (s1, b1) = run.link(src, dst, 8080).await?;
    ensure!(s1 == 200, "linking sender to 8080: {s1} {b1}");
    let src_events = run.wait_done(src, wait).await;
    let dst_events = run.events(dst).await;
    let got = received(&dst_events);
    let mut answered = BTreeSet::new();
    let (mut linked_ok, mut linked_missing, mut refused_ok, mut refused_leaked) = (0, 0, 0, 0);
    let (mut tls_ok, mut tls_other) = (0, 0);
    let (mut linked_denied, mut linked_failed) = (0, 0);
    let mut notes = Vec::new();
    for e in &src_events {
        if let Event::Sent {
            id,
            port,
            tls,
            status,
            ..
        } = e
        {
            let ok = status.is_some_and(|s| (200..300).contains(&s));
            if ok {
                answered.insert(id.clone());
            }
            match (port, tls) {
                (8080, false) if ok => {
                    if got.contains_key(id) {
                        linked_ok += 1;
                    } else {
                        linked_missing += 1;
                        notes.push(format!("answered {id} never reached the destination"));
                    }
                }
                // A host decision to refuse is an answer; anything else on a made link
                // (a 503, a dropped connection) is the link failing to carry it.
                (8080, false) if *status == Some(403) => linked_denied += 1,
                (8080, false) => {
                    linked_failed += 1;
                    if linked_failed <= 3 {
                        notes.push(format!(
                            "linked request {id} ended {status:?}, neither delivered nor decided"
                        ));
                    }
                }
                (8081, false) => {
                    if ok || got.contains_key(id) {
                        refused_leaked += 1;
                        notes.push(format!("request {id} to an unlinked port was delivered"));
                    } else {
                        refused_ok += 1;
                    }
                }
                // TLS rides the same link, on its own port (`CONNECT <name>:8080`).
                (8080, true) if ok => tls_ok += 1,
                (8080, true) => tls_other += 1,
                _ => {}
            }
        }
    }
    let sender_ids: BTreeSet<String> = src_events
        .iter()
        .filter_map(|e| match e {
            Event::Sent { id, .. } => Some(id.clone()),
            _ => None,
        })
        .collect();
    let undecided: Vec<&String> = got
        .keys()
        .filter(|id| sender_ids.contains(*id) && !answered.contains(*id))
        .collect();
    for id in &undecided {
        notes.push(format!(
            "{id} reached the destination but its sender was not answered"
        ));
    }
    let journal = run.decisions(src);
    let journalled = answered
        .iter()
        .filter(|id| journal.contains(id.as_str()))
        .count();
    let bind_failed: Vec<u16> = dst_events
        .iter()
        .filter_map(|e| match e {
            Event::BindFailed { port, .. } => Some(*port),
            _ => None,
        })
        .collect();
    for p in &bind_failed {
        notes.push(format!("the destination could not bind {p}"));
    }
    let saw_anything = !src_events.is_empty();
    let sent_of = |want_port: u32, want_tls: bool| {
        src_events
            .iter()
            .filter(|e| matches!(e, Event::Sent { port, tls, .. } if *port == want_port && *tls == want_tls))
            .count() as u64
    };
    let sent_fewest = sent_of(8080, false)
        .min(sent_of(8081, false))
        .min(sent_of(8080, true));
    if sent_fewest < n {
        notes.push(format!(
            "the sender reported {sent_fewest} of the {n} requests asked for, per kind"
        ));
    }
    let verdict = per_request_verdict(&PerRequestCounts {
        saw_anything,
        requested: n,
        sent_fewest,
        linked_ok,
        linked_failed,
        linked_missing,
        refused_leaked,
        undecided: undecided.len(),
    });
    if verdict == Verdict::Inconclusive {
        notes.push("the sender's report was empty or nothing was answered".into());
    }
    if journal.is_empty() {
        notes.push(
            "no host-effect journal found for the sender; decisions not cross-checked".into(),
        );
    }
    Ok((
        Item {
            name: "b_per_request_decisions",
            verdict,
            numbers: json!({
                "requests_per_kind": n, "linked_delivered": linked_ok,
                "linked_answered_but_missing": linked_missing,
                "linked_denied_by_host": linked_denied, "linked_failed": linked_failed,
                "unlinked_refused": refused_ok, "unlinked_leaked": refused_leaked,
                "undecided_deliveries": undecided.len(),
                "tls_answered": tls_ok, "tls_other": tls_other,
                "answered_in_host_journal": journalled, "answered_total": answered.len(),
            }),
            notes,
        },
        src,
    ))
}

async fn adversary(run: &mut Run<'_>, dst: Uuid, seed: u64) -> Result<Item> {
    let a = run
        .create(
            "adversary",
            900,
            &["adversary".into(), dst.to_string(), seed.to_string()],
        )
        .await?;
    run.wait_running(a).await?;
    let events = run.wait_done(a, Duration::from_secs(600)).await;
    let got = received(&run.events(dst).await);
    run.retire(a).await;
    let mut notes = Vec::new();
    let mut table = Vec::new();
    let mut fail = false;
    for e in &events {
        if let Event::Attempt {
            name,
            outcome,
            detail,
            id,
        } = e
        {
            let delivered = id.as_ref().is_some_and(|i| got.contains_key(i));
            let bad = match (name.as_str(), outcome) {
                (_, AttemptOutcome::Reached) => true,
                ("connection_cap", _) => false,
                (_, AttemptOutcome::Answered) => true,
                _ => delivered,
            };
            if bad {
                fail = true;
                notes.push(format!(
                    "{name}: {outcome:?} ({detail}), delivered={delivered}"
                ));
            }
            table.push(json!({"attempt": name, "outcome": outcome, "detail": detail, "delivered": delivered}));
        }
    }
    let _ = run.cancel(a).await;
    let verdict = if fail {
        Verdict::Fail
    } else if table.is_empty() {
        Verdict::Inconclusive
    } else {
        Verdict::Pass
    };
    Ok(Item {
        name: "c_adversary",
        verdict,
        numbers: json!({ "attempts": table }),
        notes,
    })
}

async fn isolation(run: &mut Run<'_>, real: Uuid, k: u64) -> Item {
    let (mut t_src, mut t_dst) = (Vec::new(), Vec::new());
    let mut bodies = BTreeSet::new();
    let mut statuses = BTreeSet::new();
    for i in 0..k {
        let unknown = Uuid::new_v4();
        let (a, b) = if i % 2 == 0 {
            (true, false)
        } else {
            (false, true)
        };
        for unknown_is_src in [a, b] {
            let start = Instant::now();
            let r = if unknown_is_src {
                run.link(unknown, real, 80).await
            } else {
                run.link(real, unknown, 80).await
            };
            let ms = start.elapsed().as_secs_f64() * 1000.0;
            if let Ok((s, body)) = r {
                statuses.insert(s);
                bodies.insert(body);
                if unknown_is_src {
                    t_src.push(ms);
                } else {
                    t_dst.push(ms);
                }
            }
        }
    }
    let identical = statuses == BTreeSet::from([404]) && bodies.len() == 1;
    let mean = |x: &[f64]| x.iter().sum::<f64>() / x.len().max(1) as f64;
    Item {
        name: "d_isolation",
        verdict: if identical {
            Verdict::Pass
        } else {
            Verdict::Fail
        },
        numbers: json!({
            "probes": k, "statuses": statuses, "distinct_bodies": bodies.len(),
            "mean_ms_unknown_src": mean(&t_src), "mean_ms_unknown_dst": mean(&t_dst),
            "welch_t": welch_t(&t_src, &t_dst),
        }),
        notes: vec![
            "timing is reported, not judged: |t| above ~3 would suggest the two 404s are \
             distinguishable by latency"
                .into(),
            "cross-trust-domain links are not exercised: every pod here is node-local".into(),
        ],
    }
}

async fn chaos(run: &mut Run<'_>, holder: Uuid, x: Uuid, y: Uuid) -> Result<Vec<Item>> {
    let mut items = Vec::new();

    // A linked pod: its cancel is refused, its reaper timeout drops the link.
    let short = run
        .create("short-lived", 60, &["serve".into(), "8080".into()])
        .await?;
    run.wait_running(short).await?;
    let (ls, lb) = run.link(holder, short, 8080).await?;
    let cancel = run.cancel(short).await?;
    let deadline = Instant::now() + Duration::from_secs(360);
    let mut dropped = false;
    while Instant::now() < deadline {
        let (_, v) = run.listing(holder).await?;
        let names_short = |r: &Value| r.to_string().contains(&short.to_string());
        if v["dropped"]
            .as_array()
            .is_some_and(|d| d.iter().any(names_short))
        {
            dropped = true;
            break;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
    items.push(Item {
        name: "e1_cancel_refused_then_drop_on_exit",
        verdict: if ls == 200 && cancel == 409 && dropped {
            Verdict::Pass
        } else {
            Verdict::Fail
        },
        numbers: json!({"link_status": ls, "cancel_status": cancel, "drop_receipt_seen": dropped}),
        notes: if ls == 200 { vec![] } else { vec![lb] },
    });

    // Links and unlinks raced on one row: the table ends consistent.
    let tasks = 64;
    let mut handles = Vec::new();
    for _ in 0..tasks {
        let client = run.node.client.clone();
        let url = run.node.url.clone();
        handles.push(tokio::spawn(async move {
            let l = client
                .post(format!("{url}/v1/pods/{x}/links"))
                .json(&json!({"dst": y, "port": 82}))
                .send()
                .await
                .map(|r| r.status().as_u16())
                .unwrap_or(0);
            let u = client
                .delete(format!("{url}/v1/pods/{x}/links/{y}/82"))
                .send()
                .await
                .map(|r| r.status().as_u16())
                .unwrap_or(0);
            (l, u)
        }));
    }
    let (mut links_done, mut unlinks_done) = (0i64, 0i64);
    for h in handles {
        let (l, u) = h.await.unwrap_or((0, 0));
        links_done += i64::from(l == 200);
        unlinks_done += i64::from(u == 200);
    }
    let (_, v) = run.listing(x).await?;
    let present = v["links"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter(|r| r["dst"] == y.to_string() && r["port"] == 82)
                .count() as i64
        })
        .unwrap_or(-1);
    items.push(Item {
        name: "e2_concurrent_link_unlink",
        verdict: race_verdict(links_done, unlinks_done, present),
        numbers: json!({"tasks": tasks, "links_done": links_done, "unlinks_done": unlinks_done, "row_present": present}),
        notes: vec![],
    });

    // An unlink while requests are in flight to a slow destination.
    let slow = run
        .create(
            "slow",
            1800,
            &[
                "serve".into(),
                "8080".into(),
                "--slow-ms".into(),
                "4000".into(),
            ],
        )
        .await?;
    run.wait_running(slow).await?;
    let sender = run
        .create(
            "slow-sender",
            1800,
            &[
                "send".into(),
                slow.to_string(),
                "8080".into(),
                "8".into(),
                "7".into(),
            ],
        )
        .await?;
    run.wait_running(sender).await?;
    run.link(sender, slow, 8080).await?;
    tokio::time::sleep(Duration::from_secs(30)).await;
    let (us, _) = run.unlink(sender, slow, 8080).await?;
    let ev = run.wait_done(sender, Duration::from_secs(300)).await;
    let statuses: BTreeMap<String, usize> = ev.iter().fold(BTreeMap::new(), |mut m, e| {
        if let Event::Sent { status, error, .. } = e {
            let key = status.map_or_else(
                || format!("error:{}", error.clone().unwrap_or_default()),
                |s| s.to_string(),
            );
            *m.entry(key).or_default() += 1;
        }
        m
    });
    items.push(Item {
        name: "e3_unlink_mid_request",
        verdict: Verdict::Recorded,
        numbers: json!({"unlink_status": us, "sender_outcomes": statuses}),
        notes: vec![
            "guest and host clocks are not correlated, so this is recorded, not judged".into(),
        ],
    });
    let _ = run.cancel(sender).await;
    let _ = run.cancel(slow).await;
    Ok(items)
}

async fn canary(run: &Run<'_>, canary: Uuid) -> Item {
    canary_item(&run.events(canary).await)
}

/// An unlinked pod passes only when it is seen listening and received
/// nothing. Silence is inconclusive, never a pass: before the probe reported
/// `listening` (found 2026-11-19), a working canary and a canary whose logs
/// were never found looked the same.
/// Item (e2): the raced row ends consistent with the 200s the node gave. A race
/// in which no link was ever made raced nothing, so it is not a pass.
fn race_verdict(links_done: i64, unlinks_done: i64, present: i64) -> Verdict {
    if links_done == 0 {
        Verdict::Inconclusive
    } else if links_done - unlinks_done == present && (0..=1).contains(&present) {
        Verdict::Pass
    } else {
        Verdict::Fail
    }
}

/// How long the standing pods (pool, destination, canary) live. They must outlive
/// every item, so the lifetime grows with the run: three hours for setup, (a),
/// (c), (d) and the chaos items, a second per differential op, and the sender's
/// wait for (b). The run cancels them when it ends, so a long bound costs nothing.
fn standing_lifetime(ops: u64, requests: u64) -> u64 {
    3 * 3600 + ops + sender_wait(requests) + 600
}

fn canary_item(ev: &[Event]) -> Item {
    let got = received(ev);
    let listening = ev.iter().any(|e| matches!(e, Event::Listening { .. }));
    let (verdict, notes) = if !got.is_empty() {
        (
            Verdict::Fail,
            vec![format!("an unlinked pod received {} request(s)", got.len())],
        )
    } else if listening {
        (Verdict::Pass, vec![])
    } else {
        (
            Verdict::Inconclusive,
            vec!["the canary never reported listening: its logs were not found".into()],
        )
    };
    Item {
        name: "f_canary_unlinked_pod",
        verdict,
        numbers: json!({"received": got.len(), "events": ev.len(), "listening": listening}),
        notes,
    }
}

/// The executor's Ed25519 public key, read from its key file by `nucleus-hostctl`.
async fn executor_key(node: &Node, bins: &Path) -> Result<[u8; 32]> {
    let out = super::node::command(
        bins.join("nucleus-hostctl"),
        &[
            "public-key".into(),
            node.state.join("executor_signing_key.der").into_os_string(),
        ],
    )
    .await?;
    let hexkey = String::from_utf8(out)?.trim().to_owned();
    let bytes = hex::decode(&hexkey)?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("executor key is not 32 bytes"))
}

fn receipts(collected: &[Value], key: Option<[u8; 32]>) -> Item {
    let Some(key) = key else {
        return Item {
            name: "g_offline_receipt_verification",
            verdict: Verdict::Inconclusive,
            numbers: json!({"collected": collected.len()}),
            notes: vec!["the executor public key could not be exported".into()],
        };
    };
    let (mut ok, mut bad) = (0, Vec::new());
    for (i, v) in collected.iter().enumerate() {
        match serde_json::from_value::<nucleus_receipt::Receipt>(v.clone()) {
            Ok(r) if r.verify(&key).is_ok() => ok += 1,
            Ok(_) => bad.push(format!("receipt {i} does not verify")),
            Err(e) => bad.push(format!("receipt {i} does not parse: {e}")),
        }
    }
    Item {
        name: "g_offline_receipt_verification",
        verdict: if !bad.is_empty() {
            Verdict::Fail
        } else if ok == 0 {
            Verdict::Inconclusive
        } else {
            Verdict::Pass
        },
        numbers: json!({"collected": collected.len(), "verified": ok}),
        notes: bad,
    }
}

/// An item whose setup failed: recorded as a failure, with why.
fn could_not_run(name: &'static str, e: &anyhow::Error) -> Item {
    Item {
        name,
        verdict: Verdict::Fail,
        numbers: json!({}),
        notes: vec![format!("the item could not run: {e:#}")],
    }
}

async fn gauntlet(node: &mut Node, bins: &Path, art: &mut Artifacts) -> Result<Report> {
    let ops = env_u64("NUCLEUS_LINKS_OPS", 2000);
    let probes = env_u64("NUCLEUS_LINKS_PROBES", 200);
    let requests = env_u64("NUCLEUS_LINKS_REQUESTS", 200);
    let pool_size = env_u64("NUCLEUS_LINKS_PODS", 8).clamp(2, 12) as usize;
    let seed = env_u64("NUCLEUS_LINKS_SEED", 0x6a75_6e74_6c65_7400);
    let lifetime = standing_lifetime(ops, requests);
    let mut items = Vec::new();
    let mut run = Run {
        node,
        art,
        receipts: Vec::new(),
    };

    let mut pool = Vec::new();
    for i in 0..pool_size {
        pool.push(
            run.create(&format!("pool-{i}"), lifetime, &["serve".into(), "80".into()])
                .await?,
        );
    }
    let dst = run
        .create("destination", lifetime, &["serve".into(), "8080".into()])
        .await?;
    let canary_pod = run
        .create("canary", lifetime, &["serve".into(), "8080".into()])
        .await?;
    for p in pool.iter().chain([&dst, &canary_pod]) {
        run.wait_running(*p).await?;
    }
    println!(
        "links-live: pool={} dst={dst} canary={canary_pod}",
        pool.len()
    );

    items.push(differential(&mut run, &mut pool, ops, seed).await);
    // An item that cannot run is a failed item in the report, never a run
    // that ends without one.
    let mut sender = None;
    match per_request(&mut run, dst, requests, seed ^ 1).await {
        Ok((b, s)) => {
            items.push(b);
            run.retire(s).await;
            sender = Some(s);
        }
        Err(e) => items.push(could_not_run("b_per_request", &e)),
    }
    match adversary(&mut run, dst, seed ^ 2).await {
        Ok(c) => items.push(c),
        Err(e) => items.push(could_not_run("c_adversary", &e)),
    }
    items.push(isolation(&mut run, dst, probes).await);
    match chaos(&mut run, pool[0], pool[1], pool[pool.len() - 1]).await {
        Ok(e) => items.extend(e),
        Err(e) => items.push(could_not_run("e_chaos", &e)),
    }
    items.push(canary(&run, canary_pod).await);
    let key = executor_key(run.node, bins).await.ok();
    items.push(receipts(&run.receipts, key));

    // Unlink everything this run made, so the pods can be cancelled.
    for p in pool.iter().chain([&dst]).chain(sender.iter()) {
        if let Ok((_, v)) = run.listing(*p).await {
            for r in v["links"].as_array().cloned().unwrap_or_default() {
                if let (Some(s), Some(d), Some(port)) =
                    (r["src"].as_str(), r["dst"].as_str(), r["port"].as_u64())
                {
                    if let (Ok(s), Ok(d)) = (Uuid::parse_str(s), Uuid::parse_str(d)) {
                        let _ = run.unlink(s, d, port as u32).await;
                    }
                }
            }
        }
    }
    let restart_target = pool[0];
    let (before, _) = run.listing(restart_target).await?;
    run.link(restart_target, pool[1], 83).await?;
    drop(run);

    // Node restart, last: is the table persisted? (Expected: not yet.)
    node.stop().await?;
    let restarted = node.restart().await;
    let mut numbers = json!({"listing_status_before": before, "restart_ok": restarted.is_ok()});
    if restarted.is_ok() {
        let r = node
            .client
            .get(format!("{}/v1/pods/{restart_target}/links", node.url))
            .send()
            .await?;
        let status = r.status().as_u16();
        let v: Value = r.json().await.unwrap_or(Value::Null);
        numbers["listing_status_after"] = json!(status);
        numbers["rows_after"] = json!(v["links"].as_array().map_or(0, Vec::len));
    }
    items.push(Item {
        name: "e4_node_restart",
        verdict: Verdict::Recorded,
        numbers,
        notes: vec![
            "the link table lives in node memory; a restart is expected to lose it until it is \
             persisted (native Olog), and this item records what actually happened"
                .into(),
        ],
    });
    Ok(Report { items })
}

#[tokio::test]
#[ignore = "requires a Linux KVM host and the link-probe rootfs; run cargo xtask links-live"]
async fn links_gauntlet() -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "links-live requires Linux");
    let var = |k: &str| {
        std::env::var_os(k)
            .map(PathBuf::from)
            .with_context(|| format!("missing {k}"))
    };
    let bins = var("NUCLEUS_HOST_EVIDENCE_BIN_DIR")?;
    let witness = var("NUCLEUS_HOST_EVIDENCE_WITNESS")?;
    let kernel = var("NUCLEUS_LINKS_KERNEL")?;
    let rootfs = var("NUCLEUS_LINKS_ROOTFS")?;
    let report_path = std::env::var_os("NUCLEUS_LINKS_REPORT").map_or_else(
        || PathBuf::from("/var/tmp/links-gauntlet-report.json"),
        PathBuf::from,
    );
    let nonce = std::env::var("NUCLEUS_HOST_EVIDENCE_NONCE")?;
    ensure!(!nonce.is_empty(), "missing nonce");
    let mut art = Artifacts::stage(&kernel, &rootfs)?;
    let root = art.root.to_string_lossy().into_owned();
    let mut node = Node::start_with(
        &bins.join("nucleus-node"),
        &nonce,
        &[
            "--artifacts-root".to_string(),
            root,
            "--egress-proxy-bin".to_string(),
            bins.join("nucleus-egress-proxy")
                .to_string_lossy()
                .into_owned(),
        ],
    )
    .await?;
    let result = gauntlet(&mut node, &bins, &mut art).await;
    let diagnostics = node.diagnostics();
    let _ = node.stop().await;
    let report = result.with_context(|| diagnostics.clone())?;
    std::fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
    for item in &report.items {
        println!(
            "links-live: {:?} {} {}",
            item.verdict, item.name, item.numbers
        );
        for n in &item.notes {
            println!("links-live:     {n}");
        }
    }
    println!("links-live: report written to {}", report_path.display());
    if report.failed() {
        bail!("the links gauntlet failed (see {})", report_path.display());
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

    /// The x86 gauntlet's numbers (2026-11-19): 63 delivered, 137 ended 503 on a
    /// made link. That is a failure, never a pass.
    #[test]
    fn a_503_on_a_made_link_fails_item_b() {
        let observed = PerRequestCounts {
            saw_anything: true,
            requested: 200,
            sent_fewest: 200,
            linked_ok: 63,
            linked_failed: 137,
            linked_missing: 0,
            refused_leaked: 0,
            undecided: 0,
        };
        assert_eq!(per_request_verdict(&observed), Verdict::Fail);
        let carried = PerRequestCounts {
            linked_ok: 200,
            linked_failed: 0,
            ..observed
        };
        assert_eq!(per_request_verdict(&carried), Verdict::Pass);
    }

    /// 2026-11-20, x86, 50,000 asked: the sender was waited on for a fixed 900 s,
    /// 19,162 of each kind were sent, nothing failed, and the item read "pass".
    #[test]
    fn a_run_that_sent_fewer_than_asked_is_not_a_pass() {
        let short = PerRequestCounts {
            saw_anything: true,
            requested: 50_000,
            sent_fewest: 19_162,
            linked_ok: 19_162,
            linked_failed: 0,
            linked_missing: 0,
            refused_leaked: 0,
            undecided: 0,
        };
        assert_eq!(per_request_verdict(&short), Verdict::Inconclusive);
        let full = PerRequestCounts {
            sent_fewest: 50_000,
            linked_ok: 50_000,
            ..short
        };
        assert_eq!(per_request_verdict(&full), Verdict::Pass);
    }

    /// 2026-11-20, x86, full scale: 64 raced link/unlink pairs got no 200 at all
    /// (both pods had outlived their lifetime) and the item read "pass".
    #[test]
    fn a_race_in_which_nothing_was_linked_is_not_a_pass() {
        assert_ne!(race_verdict(0, 0, 0), Verdict::Pass);
        assert_eq!(race_verdict(40, 39, 1), Verdict::Pass);
        assert_eq!(race_verdict(40, 40, 0), Verdict::Pass);
        assert_eq!(race_verdict(40, 40, 1), Verdict::Fail);
    }

    /// 2026-11-20, x86: at 10,000 ops and 50,000 requests the run took about
    /// 5,600 s; the standing pods lived 3,600 s, so (e1) found its holder gone.
    #[test]
    fn standing_pods_outlive_a_full_scale_run() {
        assert!(standing_lifetime(10_000, 50_000) > 5_600 + 3_600);
        assert!(standing_lifetime(10_000, 50_000) > sender_wait(50_000));
    }

    #[test]
    fn a_canary_passes_only_when_seen_listening_and_untouched() {
        assert_eq!(
            canary_item(&[]).verdict,
            Verdict::Inconclusive,
            "silence is not a pass"
        );
        let listening = Event::Listening { port: 8080 };
        assert_eq!(
            canary_item(std::slice::from_ref(&listening)).verdict,
            Verdict::Pass
        );
        let hit = Event::Received {
            id: "x".into(),
            method: "GET".into(),
            path: "/".into(),
            port: 8080,
            body_sha256: String::new(),
        };
        assert_eq!(canary_item(&[listening, hit]).verdict, Verdict::Fail);
    }

    fn pods(n: usize) -> Vec<Uuid> {
        (0..n).map(|_| Uuid::new_v4()).collect()
    }

    /// The model run against itself: every expected answer equals itself, so
    /// the comparator passes a faithful node.
    fn run_model(seed: u64, ops: usize) -> Vec<Step> {
        let slots = pods(6);
        let mut table = LinkTable::empty();
        for p in &slots {
            table.pod_started(p.as_u128(), String::new());
        }
        let mut rng = Rng::new(seed);
        (0..ops)
            .map(|index| {
                let op = gen_op(&mut rng, slots.len());
                let o = expected(op, model_apply(&mut table, &slots, op));
                Step {
                    index,
                    op,
                    model: o,
                    node: o,
                }
            })
            .collect()
    }

    #[test]
    fn a_faithful_node_passes_and_the_mix_covers_every_answer() {
        let steps = run_model(42, 2000);
        assert!(mismatches(&steps).is_empty());
        for want in [Observed::Done, Observed::Refused, Observed::NotFound] {
            assert!(
                steps.iter().any(|s| s.node == want),
                "the op mix never produced {want:?}"
            );
        }
    }

    /// Driven red: one flipped node answer is named, with its op.
    #[test]
    fn one_flipped_node_answer_is_caught() {
        let mut steps = run_model(7, 500);
        let i = steps
            .iter()
            .position(|s| s.node == Observed::Refused)
            .expect("some refusal");
        steps[i].node = Observed::Done;
        let bad = mismatches(&steps);
        assert_eq!(bad.len(), 1);
        assert!(bad[0].contains(&format!("op {i}")));
    }

    #[test]
    fn the_api_mapping_is_pod_links() {
        let l = Op::Link {
            src: 0,
            dst: 1,
            port: 80,
        };
        let u = Op::Unlink {
            src: 0,
            dst: 1,
            port: 80,
        };
        assert_eq!(expected(l, Outcome::Refused), Observed::Refused);
        assert_eq!(expected(u, Outcome::Refused), Observed::NotFound);
        assert_eq!(
            expected(Op::Cancel { pod: 0 }, Outcome::Refused),
            Observed::Refused
        );
        assert_eq!(observed(409), Observed::Refused);
        assert_eq!(observed(500), Observed::Other(500));
    }

    #[test]
    fn welch_t_is_zero_for_equal_samples_and_large_for_shifted() {
        let a = [1.0, 2.0, 3.0, 4.0];
        assert_eq!(welch_t(&a, &a), Some(0.0));
        let b = [11.0, 12.0, 13.0, 14.0];
        assert!(welch_t(&b, &a).unwrap() > 5.0);
        assert_eq!(welch_t(&[1.0], &a), None);
    }

    #[test]
    fn the_report_fails_only_on_a_fail() {
        let item = |v| Item {
            name: "x",
            verdict: v,
            numbers: json!({}),
            notes: vec![],
        };
        let r = Report {
            items: vec![
                item(Verdict::Pass),
                item(Verdict::Inconclusive),
                item(Verdict::Recorded),
            ],
        };
        assert!(!r.failed());
        let r = Report {
            items: vec![item(Verdict::Pass), item(Verdict::Fail)],
        };
        assert!(r.failed());
    }

    #[test]
    fn received_reads_ids_and_ports() {
        let ev = nucleus_link_probe::parse(&format!(
            "{}\n{}\n",
            nucleus_link_probe::line(&Event::Received {
                id: "a".into(),
                method: "GET".into(),
                path: "/r/a".into(),
                port: 8080,
                body_sha256: String::new(),
            }),
            nucleus_link_probe::line(&Event::BindFailed {
                port: 443,
                error: "denied".into(),
            })
        ));
        assert_eq!(received(&ev), BTreeMap::from([("a".to_string(), 8080)]));
    }
}
