//! A node stopped by a signal leaves nothing running (#3204). Live: Linux, KVM, root, a real
//! Firecracker pod. Invoked by `cargo xtask node-stop-live`; never a mock driver.
//!
//! Two lives end two ways:
//!
//! - **SIGTERM**: the node drains. Afterwards pod A has no VMM process, no network namespace, no
//!   jail, no host firewall rule and no jail cgroup, and its lifecycle log records the drain.
//! - **SIGKILL**: nothing can run. The test first confirms pod B's VMM really is stranded — still
//!   running with no node — because a reclaim measured against a VM that died anyway proves
//!   nothing. Then it restarts the node and requires all of B's remains gone before the node
//!   answers its first health check.
//!
//! Every observation here is made by the test from the kernel's own tables (`/proc`,
//! `ip netns list`, `iptables-save`, the cgroup and chroot trees), not by asking the node.

use anyhow::{Context, Result, ensure};
use std::{path::Path, time::Duration};
use uuid::Uuid;

use super::{Created, body, effect_pod_spec, node::Node};

/// What one pod holds on the host, observed independently of the node.
#[derive(Debug)]
struct Remains {
    /// Processes whose argv carries `--id <pod id>`: the jailer and the VMM it became.
    vmm: Vec<u32>,
    netns: bool,
    jail: bool,
    /// `iptables-save` rule lines naming the pod's host veth.
    firewall: usize,
    /// `None` on a cgroup v1 host, where the jailer's v2 leaf does not exist.
    cgroup: Option<bool>,
}

impl Remains {
    async fn observe(node: &Node, pod: Uuid) -> Result<Self> {
        let short = &pod.simple().to_string()[..8];
        let netns = run("ip", &["netns", "list"]).await?;
        let rules = run("iptables-save", &[]).await?;
        let veth = format!("veth{short}");
        let v2 = Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
        Ok(Self {
            vmm: processes_with_id(&pod.to_string())?,
            netns: netns
                .lines()
                .any(|l| l.split_whitespace().next() == Some(&format!("nuc-{short}"))),
            jail: node
                .jail_base()
                .join("firecracker")
                .join(pod.to_string())
                .exists(),
            firewall: rules
                .lines()
                .filter(|l| l.starts_with("-A ") && l.split_whitespace().any(|w| w == veth))
                .count(),
            cgroup: v2.then(|| {
                Path::new("/sys/fs/cgroup/firecracker")
                    .join(pod.to_string())
                    .exists()
            }),
        })
    }

    /// Non-vacuity: every handle the "none left" check reads must first be seen present.
    fn require_present(&self, when: &str) -> Result<()> {
        ensure!(
            !self.vmm.is_empty()
                && self.netns
                && self.jail
                && self.firewall > 0
                && self.cgroup != Some(false),
            "{when}: expected a running pod's VMM, netns, jail, firewall rules and cgroup, saw {self:?}"
        );
        Ok(())
    }

    fn leftovers(&self) -> Vec<String> {
        let mut left = Vec::new();
        if !self.vmm.is_empty() {
            left.push(format!("VMM process(es) {:?}", self.vmm));
        }
        if self.netns {
            left.push("network namespace".into());
        }
        if self.jail {
            left.push("jail directory".into());
        }
        if self.firewall > 0 {
            left.push(format!("{} host firewall rule(s)", self.firewall));
        }
        if self.cgroup == Some(true) {
            left.push("jail cgroup".into());
        }
        left
    }
}

async fn run(program: &str, args: &[&str]) -> Result<String> {
    let output = tokio::process::Command::new(program)
        .args(args)
        .kill_on_drop(true)
        .output()
        .await
        .with_context(|| format!("running {program}"))?;
    ensure!(
        output.status.success(),
        "{program} {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

/// Every process whose argv contains `--id <id>` exactly, read from `/proc`.
fn processes_with_id(id: &str) -> Result<Vec<u32>> {
    let mut found = Vec::new();
    let mut scanned = 0usize;
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
            continue; // exited between the listing and the read
        };
        scanned += 1;
        let argv: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
        if argv
            .windows(2)
            .any(|w| w[0] == b"--id" && w[1] == id.as_bytes())
        {
            found.push(pid);
        }
    }
    ensure!(scanned > 0, "read no process from /proc");
    Ok(found)
}

async fn create(node: &Node) -> Result<Uuid> {
    let created: Created = serde_json::from_slice(
        &body(
            node.client
                .post(format!("{}/v1/pods", node.url))
                .timeout(nucleus_spec::boot_budget::POD_CREATE_CLIENT_TIMEOUT)
                .json(&effect_pod_spec(&node.upstream))
                .send()
                .await?,
        )
        .await?,
    )?;
    Ok(created.id)
}

/// The two lives. Failures are collected rather than returned at the first, so one run reports
/// every leftover — which is what a red→green table needs.
async fn scenario(node: &mut Node, failures: &mut Vec<String>, seen: &mut Vec<u32>) -> Result<()> {
    // Life 1 ends in SIGTERM: the drain.
    let a = create(node).await?;
    let before = Remains::observe(node, a).await?;
    seen.extend(&before.vmm);
    before.require_present("pod A before SIGTERM")?;
    let status = node.signal("TERM", Duration::from_secs(60)).await?;
    let after = Remains::observe(node, a).await?;
    seen.extend(&after.vmm);
    for left in after.leftovers() {
        failures.push(format!("SIGTERM: pod A left its {left}"));
    }
    if !status.success() {
        failures.push(format!(
            "SIGTERM: the node exited {status}, not a clean drain"
        ));
    }
    let lifecycle = std::fs::read_to_string(
        node.state
            .join("pods")
            .join(a.to_string())
            .join("lifecycle.log"),
    )
    .unwrap_or_default();
    if !lifecycle.contains("\"pod_drained\"") {
        failures.push("SIGTERM: pod A's lifecycle log has no pod_drained record".into());
    }

    // Life 2 ends in SIGKILL; life 3 must reclaim what it stranded before it serves.
    node.restart().await?;
    let b = create(node).await?;
    let before = Remains::observe(node, b).await?;
    seen.extend(&before.vmm);
    before.require_present("pod B before SIGKILL")?;
    node.signal("KILL", Duration::from_secs(10)).await?;
    let stranded = Remains::observe(node, b).await?;
    ensure!(
        !stranded.vmm.is_empty() && stranded.netns && stranded.jail,
        "SIGKILL did not strand pod B ({stranded:?}): the reclaim below would prove nothing"
    );
    node.restart().await?;
    let reclaimed = Remains::observe(node, b).await?;
    seen.extend(&reclaimed.vmm);
    for left in reclaimed.leftovers() {
        failures.push(format!("SIGKILL + restart: pod B left its {left}"));
    }
    let lifecycle = std::fs::read_to_string(
        node.state
            .join("pods")
            .join(b.to_string())
            .join("lifecycle.log"),
    )
    .unwrap_or_default();
    if !lifecycle.contains("\"pod_reclaimed\"") {
        failures
            .push("SIGKILL + restart: pod B's lifecycle log has no pod_reclaimed record".into());
    }

    // Life 3 has no pods; its drain is trivially clean.
    let status = node.signal("TERM", Duration::from_secs(60)).await?;
    if !status.success() {
        failures.push(format!("SIGTERM with no pods: the node exited {status}"));
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires a Linux KVM host; run cargo xtask node-stop-live"]
async fn a_signalled_node_leaves_no_vm_running() -> Result<()> {
    ensure!(cfg!(target_os = "linux"), "node-stop-live requires Linux");
    let bins = std::path::PathBuf::from(
        std::env::var_os("NUCLEUS_HOST_EVIDENCE_BIN_DIR").context("missing binary directory")?,
    );
    let witness = std::path::PathBuf::from(
        std::env::var_os("NUCLEUS_HOST_EVIDENCE_WITNESS").context("missing witness path")?,
    );
    let nonce = std::env::var("NUCLEUS_HOST_EVIDENCE_NONCE")?;
    ensure!(!nonce.is_empty(), "missing nonce");
    let mut node = Node::start(&bins, &nonce).await?;
    let mut failures = Vec::new();
    let mut seen = Vec::new();
    let result = scenario(&mut node, &mut failures, &mut seen).await;
    let diagnostics = node.diagnostics();
    let _ = node.stop().await;
    // Leave the runner as it was found: SIGKILL any VMM this test saw, by the pid it observed.
    for pid in seen {
        let _ = tokio::process::Command::new("/bin/kill")
            .args(["-s", "KILL", &pid.to_string()])
            .status()
            .await;
    }
    result.with_context(|| diagnostics.clone())?;
    for failure in &failures {
        println!("node-stop-live: FAIL {failure}");
    }
    ensure!(
        failures.is_empty(),
        "{} leftover(s) after the node was stopped by a signal:\n{}\n{diagnostics}",
        failures.len(),
        failures.join("\n")
    );
    println!(
        "node-stop-live: SIGTERM drained pod A and SIGKILL+restart reclaimed pod B; nothing left"
    );
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(witness)?;
    file.write_all(nonce.as_bytes())?;
    file.sync_all()?;
    Ok(())
}
