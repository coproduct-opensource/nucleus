//! Build and run the privileged Linux integration, requiring its fresh witness.
//! Cargo's zero-selected-tests success is not evidence of a live transaction.
use anyhow::{Context, Result, ensure};
use std::{path::Path, process::Command};

pub fn run(root: &Path, bins: &Path, sudo: bool) -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "host-evidence-live requires Linux and KVM"
    );
    let bins = bins.canonicalize().context("binary directory")?;
    for name in ["nucleus-node", "nucleus-hostctl", "nucleus-audit"] {
        ensure!(
            bins.join(name).is_file(),
            "missing {}",
            bins.join(name).display()
        );
    }
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
        .arg(format!("NUCLEUS_HOST_EVIDENCE_NONCE={nonce}"))
        .arg(test)
        .args([
            "host_evidence_live::real_guest_host_evidence",
            "--ignored",
            "--exact",
            "--nocapture",
        ]);
    let status = command.status()?;
    ensure!(status.success(), "live host evidence test failed: {status}");
    ensure!(
        std::fs::read_to_string(&witness).context("live test produced no success witness")?
            == nonce,
        "live test witness does not identify this invocation"
    );
    println!(
        "host-evidence-live: real guest, host authorization/outcome, offline verification and cleanup passed"
    );
    Ok(())
}
