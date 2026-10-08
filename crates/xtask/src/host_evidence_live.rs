//! Build and run the privileged Linux integration, requiring its fresh witness.
//! Cargo's zero-selected-tests success is not evidence of a live transaction.
use anyhow::{Context, Result, ensure};
use std::{path::Path, process::Command};

/// One privileged live integration in the CLI's test binary, and what it proves when it passes.
pub enum Live {
    /// `host-evidence-live`: host authorization and outcome on a real guest transaction.
    HostEvidence,
    /// `node-stop-live`: a node stopped by SIGTERM drains its pods, and one stopped by SIGKILL
    /// has its stranded VMM reclaimed at the next start (#3204).
    NodeStop,
    /// `cross-pod-live`: C2 on a real Firecracker boot. Two pods on one node each see only their
    /// own lineage over their own vsock, and the operator sees both (replaces
    /// `scripts/firecracker/podlist-boot-check.sh`).
    CrossPod {
        /// The guest kernel to boot.
        kernel: std::path::PathBuf,
        /// The CI podlist rootfs: the lineage probe baked in, guest-init built with
        /// `ci-podlist-probe`.
        rootfs: std::path::PathBuf,
    },
}

impl Live {
    fn test(&self) -> &'static str {
        match self {
            Live::HostEvidence => "host_evidence_live::real_guest_host_evidence",
            Live::NodeStop => {
                "host_evidence_live::node_stop::a_signalled_node_leaves_no_vm_running"
            }
            Live::CrossPod { .. } => {
                "host_evidence_live::cross_pod::two_pods_each_see_only_their_own_lineage"
            }
        }
    }
    fn passed(&self) -> &'static str {
        match self {
            Live::HostEvidence => {
                "host-evidence-live: real guest, host authorization/outcome, offline verification and cleanup passed"
            }
            Live::NodeStop => {
                "node-stop-live: each VMM was pid 1 of its own pid namespace; cancel reaped a real pod, SIGTERM drained one and SIGKILL+restart reclaimed one; no VMM, netns, jail, firewall rule or cgroup left"
            }
            Live::CrossPod { .. } => {
                "cross-pod-live: CONTAINED: on one node, A's vsock POD_LIST served {A, its child C} and B's served {B}; each root was served its own id, and both views are strict subsets of the operator's"
            }
        }
    }
    /// The binaries this integration runs from `--bin-dir`.
    fn bins(&self) -> &'static [&'static str] {
        match self {
            Live::HostEvidence | Live::NodeStop => {
                &["nucleus-node", "nucleus-hostctl", "nucleus-audit"]
            }
            Live::CrossPod { .. } => &["nucleus-node"],
        }
    }
    /// Inputs passed to the test by environment.
    fn env(&self) -> Vec<(&'static str, &std::path::Path)> {
        match self {
            Live::HostEvidence | Live::NodeStop => Vec::new(),
            Live::CrossPod { kernel, rootfs } => vec![
                ("NUCLEUS_CROSS_POD_KERNEL", kernel.as_path()),
                ("NUCLEUS_CROSS_POD_ROOTFS", rootfs.as_path()),
            ],
        }
    }
}

pub fn run(root: &Path, bins: &Path, sudo: bool) -> Result<()> {
    run_live(root, bins, sudo, Live::HostEvidence)
}

pub fn run_live(root: &Path, bins: &Path, sudo: bool, live: Live) -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "live integrations require Linux and KVM"
    );
    let bins = bins.canonicalize().context("binary directory")?;
    for (key, path) in live.env() {
        ensure!(path.is_file(), "{key}: missing {}", path.display());
    }
    for name in live.bins() {
        ensure!(
            bins.join(name).is_file(),
            "missing {}",
            bins.join(name).display()
        );
    }
    let test = cli_test_executable(root)?;
    let directory = tempfile::tempdir()?;
    let witness = directory.path().join("verified");
    // Fresh directory identity is unique to this invocation and independent of
    // the producer. The marker is written only after verification AND cleanup.
    let nonce = format!(
        "host-evidence-{}-{}",
        std::process::id(),
        directory.path().display()
    );
    let mut command = if sudo {
        let mut c = Command::new("sudo");
        c.args(["--", "env"]);
        c
    } else {
        Command::new("env")
    };
    command
        .arg(format!("NUCLEUS_HOST_EVIDENCE_BIN_DIR={}", bins.display()))
        .arg(format!(
            "NUCLEUS_HOST_EVIDENCE_WITNESS={}",
            witness.display()
        ))
        .arg(format!("NUCLEUS_HOST_EVIDENCE_NONCE={nonce}"));
    for (key, path) in live.env() {
        let path = path.canonicalize().with_context(|| key.to_string())?;
        command.arg(format!("{key}={}", path.display()));
    }
    command
        .arg(&test)
        .args([live.test(), "--ignored", "--exact", "--nocapture"]);
    let status = command.status()?;
    ensure!(status.success(), "live host evidence test failed: {status}");
    ensure!(
        std::fs::read_to_string(&witness).context("live test produced no success witness")?
            == nonce,
        "live test witness does not identify this invocation"
    );
    println!("{}", live.passed());
    Ok(())
}

/// Build the `nucleus` CLI's test executable, which holds the live
/// integrations (`#[ignore]`d), and return its path. Shared with
/// `live-boot-evidence`, whose collector lives in the same binary.
pub(crate) fn cli_test_executable(root: &Path) -> Result<String> {
    let build = Command::new("cargo")
        .current_dir(root)
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_PROFILE_DEV_DEBUG", "0")
        .env("CARGO_PROFILE_TEST_DEBUG", "0")
        .args([
            "test",
            "-p",
            "nucleus-cli",
            "--bin",
            "nucleus",
            "--no-run",
            "--message-format=json",
        ])
        .output()?;
    std::io::Write::write_all(&mut std::io::stderr(), &build.stderr)?;
    ensure!(build.status.success(), "building live evidence test failed");
    let mut executables = Vec::new();
    for line in build
        .stdout
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
    {
        let value: serde_json::Value = serde_json::from_slice(line)?;
        if value["reason"] == "compiler-artifact"
            && value["profile"]["test"] == true
            && value["target"]["name"] == "nucleus"
        {
            if let Some(path) = value["executable"].as_str() {
                executables.push(path.to_owned());
            }
        }
    }
    let [test] = executables.as_slice() else {
        anyhow::bail!("expected one CLI test executable, got {executables:?}")
    };
    Ok(test.clone())
}
