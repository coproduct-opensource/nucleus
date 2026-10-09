//! The live boot's software TPM: a swtpm the collector starts, exposes to the
//! node as a kernel TPM device through the vTPM proxy, measures the node's
//! binaries into, and pins, all before the node starts.
//!
//! What this is, said plainly, because every label downstream depends on it:
//! no hardware holds the AK, and the PCR 10 measurements are the collector's,
//! standing in for the kernel's IMA on a TPM the kernel never measured into.
//! So the node claims `software-tpm:<source>`, the appraiser accepts the AK
//! only through `--allow-software-tpm-pin`, and every result is labelled
//! `software_tpm`. What it does prove is the rest of the chain: the node
//! quotes through the same device path a hardware node uses, the quote binds
//! the node's executor key, and the appraisal is `Attested` only when the
//! binaries that ran are the binaries this build's reference names.
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
    AkTemplate, Attester, DeviceTransport, LogSources, Tpm, default_pcrs, measure_into_pcr10,
};
use nucleus_node_evidence::tpm::AkPublic;
use nucleus_spec::live_boot::{Measured, MeasuredHow, SoftwareTpm};

/// A running swtpm behind a vTPM proxy device. Stopped on drop, which
/// removes the device.
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

/// `New TPM device: /dev/tpm1 (major/minor = 253/1)` → `1`.
fn device_number(line: &str) -> Option<u32> {
    line.split_once("New TPM device: /dev/tpm")?
        .1
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

/// Start swtpm on a vTPM proxy and return the resource-managed device.
fn start(state: &Path) -> Result<(Child, PathBuf)> {
    let modprobe = Command::new("modprobe")
        .arg("tpm_vtpm_proxy")
        .status()
        .context("running modprobe tpm_vtpm_proxy")?;
    ensure!(modprobe.success(), "modprobe tpm_vtpm_proxy: {modprobe}");
    std::fs::create_dir_all(state)?;
    // swtpm announces its device on stdout. A file, never a pipe: a pipe
    // closed after the announcement would kill swtpm at its next write.
    let announced = state.join("swtpm.out");
    let mut child = Command::new("swtpm")
        .args(["chardev", "--vtpm-proxy", "--tpm2", "--tpmstate"])
        .arg(format!("dir={}", state.display()))
        .stdout(std::fs::File::create(&announced)?)
        .spawn()
        .context("starting swtpm (is it installed?)")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    let n = loop {
        let text = std::fs::read_to_string(&announced).unwrap_or_default();
        if let Some(n) = text.lines().find_map(device_number) {
            break n;
        }
        if let Some(status) = child.try_wait()? {
            bail!("swtpm exited ({status}) without naming its device: {text:?}");
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            bail!("swtpm named no device within 10 s: {text:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    // The kernel registers the chip, and sends it TPM2_Startup, before the
    // resource-managed node appears.
    let device = PathBuf::from(format!("/dev/tpmrm{n}"));
    while !device.exists() {
        if Instant::now() > deadline {
            let _ = child.kill();
            bail!("{} never appeared", device.display());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok((child, device))
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
    let (child, device) = start(&dir.join("state"))?;
    // From here `Running` owns the child, so every early return stops it.
    let mut running = Running {
        child,
        record: SoftwareTpm::NotUsed,
        node_args: Vec::new(),
    };
    let logs = dir.join("logs");
    let open = || -> Result<Tpm<DeviceTransport>> {
        Ok(Tpm::new(DeviceTransport::open(&device).with_context(
            || format!("opening {}", device.display()),
        )?))
    };
    let mut tpm = open()?;
    let measured = measure_into_pcr10(&mut tpm, &logs, binaries)
        .context("measuring the node's binaries into the software TPM")?;
    let claim = AkAnchorClaim::SoftwareTpm {
        source: source.into(),
    };
    let ak = Attester::new(
        tpm,
        AkTemplate::DefaultEccP256,
        default_pcrs(),
        LogSources::under(&logs),
        claim,
    )
    .ak_public()
    .context("reading the software TPM's AK")?;
    let pin = hex::encode(
        AkPublic::from_tpm2b_public(&ak)
            .map_err(|e| anyhow::anyhow!("the software TPM's AK: {e}"))?
            .spki_sha256(),
    );
    running.node_args = vec![
        format!("--node-evidence-tpm={}", device.display()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_device_number_is_read_from_swtpms_announcement() {
        assert_eq!(
            device_number("New TPM device: /dev/tpm1 (major/minor = 253/1)"),
            Some(1)
        );
        assert_eq!(
            device_number("New TPM device: /dev/tpm12 (major/minor = 253/12)"),
            Some(12)
        );
        assert_eq!(device_number("swtpm: something else"), None);
    }
}
