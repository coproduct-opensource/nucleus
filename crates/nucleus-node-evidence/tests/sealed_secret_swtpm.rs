//! Secrets sealed to the boot PCRs, against real software TPMs (libtpms via
//! swtpm): the TPM layer under the node's sealed Ed25519 keys (A2).
//!
//! Each test starts its own swtpm processes (fresh state, so fresh seeds).
//! Needs `swtpm` on `PATH` (or `NUCLEUS_SWTPM_BIN`). Ignored by default; an
//! ignored test is reported as ignored, never as a pass.
#![cfg(feature = "attester")]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use nucleus_node_evidence::key_attestation::{boot_policy_pcrs, policy_pcr_digest};
use nucleus_node_evidence::tpm_key::{AnyTransport, MAX_SEALED_BYTES, TpmEndpoint, seal, unseal};

/// One swtpm process with its own state directory, killed on drop.
struct Swtpm {
    child: Child,
    dir: PathBuf,
    addr: String,
}

impl Swtpm {
    fn start() -> Self {
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let dir = std::env::temp_dir().join(format!(
            "nucleus-swtpm-sealed-{}-{port}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = std::env::var("NUCLEUS_SWTPM_BIN").unwrap_or_else(|_| "swtpm".into());
        let child = Command::new(bin)
            .args(["socket", "--tpm2", "--tpmstate"])
            .arg(format!("dir={}", dir.display()))
            .args(["--server"])
            .arg(format!("type=tcp,port={port},bindaddr=127.0.0.1"))
            .args(["--ctrl"])
            .arg(format!(
                "type=tcp,port={},bindaddr=127.0.0.1",
                port.checked_add(1).unwrap()
            ))
            .args(["--flags", "not-need-init,startup-clear"])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("swtpm on PATH (or NUCLEUS_SWTPM_BIN)");
        let addr = format!("127.0.0.1:{port}");
        for _ in 0..100 {
            if std::net::TcpStream::connect(&addr).is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        std::thread::sleep(Duration::from_millis(100));
        Self { child, dir, addr }
    }

    fn tpm(&self) -> nucleus_node_evidence::attester::Tpm<AnyTransport> {
        TpmEndpoint::Socket(self.addr.clone()).connect().unwrap()
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const SECRET: [u8; 32] = [0xA5; 32];

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The secret round-trips, more than once (every handle and session is
/// released), its policy is `PolicyPCR` over the boot PCRs' current values,
/// and neither stored part contains it.
#[test]
#[ignore = "needs swtpm on PATH"]
fn a_sealed_secret_unseals_to_itself() {
    let a = Swtpm::start();
    let mut tpm = a.tpm();
    let blob = seal(&mut tpm, &boot_policy_pcrs(), &SECRET).unwrap();
    assert_eq!(blob.policy_pcrs(), &boot_policy_pcrs());
    let now = tpm.pcr_read(&boot_policy_pcrs()).unwrap();
    assert_eq!(
        blob.auth_policy(),
        &policy_pcr_digest(&boot_policy_pcrs(), &now).unwrap()
    );
    assert!(blob.policy_matches(&now).unwrap());
    for part in [blob.public(), blob.private()] {
        assert!(!contains(part, &SECRET), "the secret is in a stored part");
    }
    assert_eq!(unseal(&mut tpm, &blob).unwrap().as_slice(), SECRET);
    assert_eq!(unseal(&mut tpm, &blob).unwrap().as_slice(), SECRET);
    // Out of range sizes are refused before the TPM sees them.
    assert!(seal(&mut tpm, &boot_policy_pcrs(), &[]).is_err());
    assert!(seal(&mut tpm, &boot_policy_pcrs(), &[1; MAX_SEALED_BYTES + 1]).is_err());
}

/// After a policy PCR moves (8, the kernel command line), the TPM refuses to
/// unseal, for its policy. A PCR outside the policy moves nothing.
#[test]
#[ignore = "needs swtpm on PATH"]
fn extending_a_policy_pcr_stops_the_unseal() {
    let a = Swtpm::start();
    let mut tpm = a.tpm();
    let blob = seal(&mut tpm, &boot_policy_pcrs(), &SECRET).unwrap();
    tpm.pcr_extend(16, &[0x16; 32]).unwrap();
    assert_eq!(unseal(&mut tpm, &blob).unwrap().as_slice(), SECRET);
    tpm.pcr_extend(8, &[0x08; 32]).unwrap();
    let err = unseal(&mut tpm, &blob).unwrap_err();
    assert!(err.is_policy_failure(), "refused for its policy: {err}");
    let now = tpm.pcr_read(&boot_policy_pcrs()).unwrap();
    assert!(!blob.policy_matches(&now).unwrap());
}

/// A blob moved to another TPM does not load there: its wrapping is under the
/// first TPM's owner seed.
#[test]
#[ignore = "needs swtpm on PATH"]
fn a_blob_moved_to_another_tpm_does_not_unseal() {
    let a = Swtpm::start();
    let b = Swtpm::start();
    let blob = seal(&mut a.tpm(), &boot_policy_pcrs(), &SECRET).unwrap();
    let err = unseal(&mut b.tpm(), &blob).unwrap_err();
    assert!(
        err.is_integrity_failure(),
        "refused for its wrapping: {err}"
    );
    assert_eq!(unseal(&mut a.tpm(), &blob).unwrap().as_slice(), SECRET);
}
