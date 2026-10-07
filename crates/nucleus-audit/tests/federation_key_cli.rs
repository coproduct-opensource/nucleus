//! `verify-node-evidence --jwks --federation-key-attestation`: is the
//! issuer's JWKS key TPM-resident and bound to the boot the quote measured?
//! (ADR 0012.)
//!
//! The fixtures in `tests/fixtures/federation-key/` are real TPM bytes:
//! `nucleus-node-evidence/examples/federation_key.rs capture` against swtpm
//! 0.7.3 (libtpms). It created a federation key bound to PCRs
//! 0,2,4,7,8,9,14, certified it with the default ECC AK, quoted over nonce
//! `77…77` (`evidence.json`), extended PCR 8, and quoted again over `78…78`
//! (`evidence-moved.json`); the TPM then refused to sign
//! (`sign-after-extend.txt`). The evidence binds executor key `5e…5e` and
//! the SHA-256 of `jwks.json`'s bytes.
//!
//! `tests/fixtures/federation-key-vtpm/` is the same capture on a cloud
//! provider's Shielded VM vTPM (x86, Ubuntu 24.04, kernel 7.0), with the
//! provider's ECC AK template (NV `0x01c10003`), the real boot event log and
//! IMA log, on 2026-10-07. `ak-from-cloud-api.pem` is the AK the provider's
//! API reported for that instance; `ak-pin.txt` is its SPKI SHA-256, and the
//! AK the evidence carries hashes to the same value.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use base64::Engine as _;
use sha2::{Digest, Sha256};

const EXECUTOR: &str = "5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e";

const SWTPM: &str = "federation-key";
const VTPM: &str = "federation-key-vtpm";

fn fixture_in(set: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(set)
        .join(name)
}

fn fixture(name: &str) -> PathBuf {
    fixture_in(SWTPM, name)
}

fn reference(dir: &Path) -> PathBuf {
    let not_checked = serde_json::json!({ "not_checked": "software TPM: no firmware or IMA" });
    let r = serde_json::json!({
        "profile": "nucleus-node-reference/v1",
        "tag-id": "swtpm-federation-key",
        "reference-values": {
            "pcrs": {},
            "secure_boot": not_checked,
            "efi_applications": not_checked,
            "boot_files": not_checked,
            "kernel_cmdline": not_checked,
            "ima": not_checked,
        }
    });
    let path = dir.join("reference.json");
    std::fs::write(&path, serde_json::to_vec(&r).unwrap()).unwrap();
    path
}

fn verify(dir: &Path, evidence: &str, nonce: u8, attestation: &Path) -> Output {
    verify_in(SWTPM, dir, &fixture(evidence), nonce, attestation)
}

fn verify_in(set: &str, dir: &Path, evidence: &Path, nonce: u8, attestation: &Path) -> Output {
    let jwks = std::fs::read(fixture_in(set, "jwks.json")).unwrap();
    let pin = std::fs::read_to_string(fixture_in(set, "ak-pin.txt")).unwrap();
    Command::new(env!("CARGO_BIN_EXE_nucleus-audit"))
        .arg("verify-node-evidence")
        .arg("--evidence")
        .arg(evidence)
        .arg("--reference")
        .arg(reference(dir))
        .args(["--executor-ed25519", EXECUTOR])
        .args(["--federation", &hex::encode(Sha256::digest(&jwks))])
        .args(["--nonce", &hex::encode([nonce; 32])])
        .args(["--operator-pin", &format!("operator={}", pin.trim())])
        .arg("--jwks")
        .arg(fixture_in(set, "jwks.json"))
        .arg("--federation-key-attestation")
        .arg(attestation)
        .output()
        .unwrap()
}

fn stdout_json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}: stdout {:?} stderr {:?}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn attestation() -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(fixture("federation-keys.json")).unwrap()).unwrap()
}

fn write(dir: &Path, name: &str, doc: &serde_json::Value) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, serde_json::to_vec(doc).unwrap()).unwrap();
    p
}

#[test]
fn a_tpm_resident_key_on_an_attested_boot_passes() {
    let dir = tempfile::tempdir().unwrap();
    let out = verify(
        dir.path(),
        "evidence.json",
        0x77,
        &fixture("federation-keys.json"),
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let v = stdout_json(&out);
    assert_eq!(
        v["ear"]["submods"]["node"]["ear.status"], "affirming",
        "{v}"
    );
    let keys = v["federation_keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["residency"], "tpm_bound");
    assert_eq!(
        keys[0]["policy_pcrs"],
        serde_json::json!([0, 2, 4, 7, 8, 9, 14])
    );
}

#[test]
fn a_file_key_fails_and_says_it_is_not_tpm_resident() {
    let dir = tempfile::tempdir().unwrap();
    let mut doc = attestation();
    doc["keys"][0]["custody"] = serde_json::json!({ "file": { "reason": "waived" } });
    let out = verify(
        dir.path(),
        "evidence.json",
        0x77,
        &write(dir.path(), "file.json", &doc),
    );
    assert!(!out.status.success());
    assert_eq!(
        stdout_json(&out)["federation_keys"][0]["residency"],
        "not_tpm_resident"
    );
    assert!(stderr(&out).contains("not TPM-bound"), "{}", stderr(&out));
}

#[test]
fn a_rewritten_policy_digest_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let mut doc = attestation();
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut public = b64
        .decode(doc["keys"][0]["custody"]["tpm"]["public"].as_str().unwrap())
        .unwrap();
    public[12] ^= 0x01; // the first byte of authPolicy
    doc["keys"][0]["custody"]["tpm"]["public"] = b64.encode(&public).into();
    let out = verify(
        dir.path(),
        "evidence.json",
        0x77,
        &write(dir.path(), "tampered.json", &doc),
    );
    assert!(!out.status.success());
    assert!(stderr(&out).contains("certified Name"), "{}", stderr(&out));
}

#[test]
fn a_key_from_before_the_boot_state_moved_is_refused() {
    // Same TPM, same AK, same key; PCR 8 extended between the certification
    // and this quote. The TPM refuses to sign with the key now, and the
    // verifier sees why: its policy is not over the quoted values.
    assert!(
        std::fs::read_to_string(fixture("sign-after-extend.txt"))
            .unwrap()
            .starts_with("REFUSED by the TPM for its policy")
    );
    let dir = tempfile::tempdir().unwrap();
    let out = verify(
        dir.path(),
        "evidence-moved.json",
        0x78,
        &fixture("federation-keys.json"),
    );
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("authPolicy is not PolicyPCR over the quoted PCR values"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn the_key_check_needs_both_documents() {
    let out = Command::new(env!("CARGO_BIN_EXE_nucleus-audit"))
        .arg("verify-node-evidence")
        .args([
            "--evidence",
            "e",
            "--reference",
            "r",
            "--executor-ed25519",
            EXECUTOR,
        ])
        .args(["--nonce", &hex::encode([0x77u8; 32])])
        .arg("--jwks")
        .arg(fixture("jwks.json"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("--federation-key-attestation"),
        "{}",
        stderr(&out)
    );
}

/// The pin is the provider's word for this instance's AK, not the node's.
#[test]
fn the_cloud_vtpm_pin_is_the_ak_the_provider_api_reported() {
    let pem = std::fs::read_to_string(fixture_in(VTPM, "ak-from-cloud-api.pem")).unwrap();
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .unwrap();
    let pin = std::fs::read_to_string(fixture_in(VTPM, "ak-pin.txt")).unwrap();
    assert_eq!(hex::encode(Sha256::digest(der)), pin.trim());
}

#[test]
fn a_cloud_vtpm_key_is_tpm_bound_on_an_attested_boot() {
    let dir = tempfile::tempdir().unwrap();
    let out = verify_in(
        VTPM,
        dir.path(),
        &fixture_in(VTPM, "evidence.json"),
        0x77,
        &fixture_in(VTPM, "federation-keys.json"),
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let v = stdout_json(&out);
    assert_eq!(v["ear"]["submods"]["node"]["ear.status"], "affirming");
    assert_eq!(v["federation_keys"][0]["residency"], "tpm_bound", "{v}");
}

#[test]
fn after_the_cloud_vtpms_boot_state_moved_nothing_passes() {
    // PCR 8 was extended after the certification. The vTPM refused to sign;
    // the moved quote's boot log no longer replays (the extension was not
    // logged), and with the log set aside the key's policy is visibly not
    // over the quoted values.
    assert!(
        std::fs::read_to_string(fixture_in(VTPM, "sign-after-extend.txt"))
            .unwrap()
            .starts_with("REFUSED by the TPM for its policy")
    );
    let dir = tempfile::tempdir().unwrap();
    let attestation = fixture_in(VTPM, "federation-keys.json");
    let moved = fixture_in(VTPM, "evidence-moved.json");
    let out = verify_in(VTPM, dir.path(), &moved, 0x78, &attestation);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("does not replay to quoted PCR 8"),
        "{}",
        stderr(&out)
    );
    let mut e: serde_json::Value = serde_json::from_slice(&std::fs::read(&moved).unwrap()).unwrap();
    e["boot_event_log"] = serde_json::json!({ "absent": "set aside by this test" });
    let stripped = write(dir.path(), "moved-no-log.json", &e);
    let out = verify_in(VTPM, dir.path(), &stripped, 0x78, &attestation);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("authPolicy is not PolicyPCR over the quoted PCR values"),
        "{}",
        stderr(&out)
    );
}
