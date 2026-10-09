//! The live boot's software TPM: a swtpm the collector starts on a loopback
//! socket, measures the node's binaries into, and pins, all before the node
//! starts. The node then quotes through that socket
//! (`--node-evidence-software-tpm`).
//!
//! What this is, said plainly, because every label downstream depends on it:
//! no hardware holds the AK, and the PCR 10 measurements are the collector's,
//! standing in for the kernel's IMA on a TPM the kernel never measured into.
//! So the node claims `software-tpm:<source>`, the appraiser accepts the AK
//! only through `--allow-software-tpm-pin`, and every result is labelled
//! `software_tpm`. What it does prove is the rest of the chain: the node's
//! attester quotes over the same TPM commands a hardware node sends, the
//! quote binds the node's executor key, and the appraisal is `Attested` only
//! when the binaries that ran are the binaries this build's reference names.
//!
//! A socket, not the kernel's vTPM proxy: the CI runner's kernel does not
//! build `tpm_vtpm_proxy` (measured: not in its modules or modules-extra).
//!
//! The pin is read per run from the TPM the collector just started, never
//! from a committed fixture: a committed swtpm state would publish the seed
//! behind a pinned AK, and anyone holding it could sign quotes a relying
//! party configured with that pin would accept.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use nucleus_node_evidence::AkAnchorClaim;
use nucleus_node_evidence::attester::{
    AkTemplate, Attester, LogSources, SocketTransport, Tpm, default_pcrs, measure_into_pcr10,
};
use nucleus_node_evidence::tpm::AkPublic;
use nucleus_spec::live_boot::{Measured, MeasuredHow, SoftwareTpm};

/// A running swtpm. Stopped on drop.
pub(super) struct Running {
    child: Child,
    /// What the collection records.
    pub(super) record: SoftwareTpm,
    /// The node flags that hand it the TPM, the anchor, the reference, the
    /// pin and the log directory.
    pub(super) node_args: Vec<String>,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A loopback port nothing is listening on now.
fn free_port() -> Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

/// Start swtpm on loopback and wait until its data socket accepts. Returns
/// the child (owned by the caller from here) and the address.
fn start(state: &Path) -> Result<(Child, String)> {
    std::fs::create_dir_all(state)?;
    let (data, ctrl) = (free_port()?, free_port()?);
    ensure!(data != ctrl, "no two free loopback ports");
    let mut child = Command::new("swtpm")
        .args(["socket", "--tpm2", "--tpmstate"])
        .arg(format!("dir={}", state.display()))
        .arg("--server")
        .arg(format!("type=tcp,port={data},bindaddr=127.0.0.1"))
        .arg("--ctrl")
        .arg(format!("type=tcp,port={ctrl},bindaddr=127.0.0.1"))
        .args(["--flags", "not-need-init,startup-clear"])
        .spawn()
        .context("starting swtpm (is it installed?)")?;
    let addr = format!("127.0.0.1:{data}");
    let deadline = Instant::now() + Duration::from_secs(10);
    // Probe the control port, never the data port: swtpm serves one data
    // client at a time, and a probe there would be that client.
    let ctrl_addr = format!("127.0.0.1:{ctrl}");
    while std::net::TcpStream::connect(&ctrl_addr).is_err() {
        if let Some(status) = child.try_wait()? {
            bail!("swtpm exited ({status}) before serving {addr}");
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("swtpm did not serve {addr} within 10 s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok((child, addr))
}

/// Start the software TPM, measure `binaries` (install paths) into its PCR 10
/// with the log under `dir`, read its AK, and return the node flags that use
/// all of it with `reference`.
pub(super) fn prepare(
    source: &str,
    reference: &Path,
    binaries: &[PathBuf],
    dir: &Path,
) -> Result<Running> {
    ensure!(
        reference.is_file(),
        "the reference manifest {} does not exist",
        reference.display()
    );
    let (child, addr) = start(&dir.join("state"))?;
    // From here `Running` owns the child, so every early return stops it.
    let mut running = Running {
        child,
        record: SoftwareTpm::NotUsed,
        node_args: Vec::new(),
    };
    let logs = dir.join("logs");
    // One connection, closed before the node opens its own: swtpm serves one
    // client at a time.
    let mut tpm =
        Tpm::new(SocketTransport::connect(&addr).with_context(|| format!("connecting to {addr}"))?);
    let measured = measure_into_pcr10(&mut tpm, &logs, binaries)
        .context("measuring the node's binaries into the software TPM")?;
    let ak = Attester::new(
        tpm,
        AkTemplate::DefaultEccP256,
        default_pcrs(),
        LogSources::under(&logs),
        AkAnchorClaim::SoftwareTpm {
            source: source.into(),
        },
    )
    .ak_public()
    .context("reading the software TPM's AK")?;
    let pin = hex::encode(
        AkPublic::from_tpm2b_public(&ak)
            .map_err(|e| anyhow::anyhow!("the software TPM's AK: {e}"))?
            .spki_sha256(),
    );
    running.node_args = vec![
        format!("--node-evidence-software-tpm={addr}"),
        format!("--node-evidence-anchor=software-tpm:{source}"),
        format!("--node-evidence-reference={}", reference.display()),
        format!("--node-evidence-ak-pin={pin}"),
        format!("--node-evidence-logs={}", logs.display()),
    ];
    running.record = SoftwareTpm::Pinned {
        source: source.into(),
        ak_spki_sha256: pin,
        measured: measured
            .into_iter()
            .map(|e| Measured {
                path: e.path,
                sha256: e.digest,
                how: MeasuredHow::ConfiguredFile,
            })
            .collect(),
    };
    Ok(running)
}
