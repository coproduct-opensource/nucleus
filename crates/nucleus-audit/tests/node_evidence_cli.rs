//! `verify-node-evidence` and the composite verdict of `verify-execution`.
//!
//! The fixtures are epoch evidence from this repository's attester
//! (`nucleus-node-evidence/examples/swtpm_attest.rs`) against swtpm 0.7.3, bound
//! to the Ed25519 key of seed `[7; 32]` (public key computed independently with
//! `openssl pkey`). PCR 16 was extended once before the quotes; the AK is the
//! default ECC template, fingerprinted by the attester at capture.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ed25519_dalek::SigningKey;
use nucleus_ci_verdict::execution::{
    Backend, ExecutionClaim, ExecutionSchema, NodePlatform, RecordedExecution,
};
use nucleus_receipt::{Receipt, Session};
use sha2::{Digest, Sha256};

const AK_PIN: &str = "14bc2cd48c5f01eed8779e142e391552e5003d1e58a9ae2728bbe8d8e3a6e9ed";
const SOURCE: &str = "swtpm-operator";
/// `tpm2_pcrread sha256:16` at capture.
const PCR16: &str = "33e611205e3088f23f3c7895d8b9adebf4d21934b09e11afdf3bd1dc2b19b31b";
const EPOCH3_IAT: u64 = 1_791_250_000;
const EXECUTOR: &str = "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn audit(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nucleus-audit"))
        .args(args)
        .output()
        .unwrap()
}

fn reference(dir: &Path, pcr16: &str) -> PathBuf {
    let not_checked = serde_json::json!({ "not_checked": "software TPM: no firmware or IMA" });
    let r = serde_json::json!({
        "profile": "nucleus-node-reference/v1",
        "tag-id": "swtpm-audit",
        "reference-values": {
            "pcrs": { "16": pcr16 },
            "secure_boot": not_checked,
            "efi_applications": not_checked,
            "boot_files": not_checked,
            "kernel_cmdline": not_checked,
            "ima": not_checked,
        }
    });
    let path = dir.join(format!("reference-{}.json", &pcr16[..8]));
    std::fs::write(&path, serde_json::to_vec(&r).unwrap()).unwrap();
    path
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{e}: stdout {:?} stderr {:?}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

#[test]
fn the_seed_key_is_the_one_the_fixtures_bind() {
    let key = SigningKey::from_bytes(&[7; 32]);
    assert_eq!(hex::encode(key.verifying_key().to_bytes()), EXECUTOR);
}

#[test]
fn verify_node_evidence_affirms_only_with_a_pin_fresh_evidence_and_matching_pcrs() {
    let dir = tempfile::tempdir().unwrap();
    let evidence = fixture("node-evidence-swtpm-epoch3.json");
    let good = reference(dir.path(), PCR16);
    let pin = format!("{SOURCE}={AK_PIN}");
    let at = |t: u64| t.to_string();
    let base = |reference: &Path, time: &str| -> Vec<String> {
        vec![
            "verify-node-evidence".into(),
            "--evidence".into(),
            evidence.display().to_string(),
            "--reference".into(),
            reference.display().to_string(),
            "--executor-ed25519".into(),
            EXECUTOR.into(),
            "--receipt-time".into(),
            time.into(),
        ]
    };
    let run = |mut args: Vec<String>, extra: &[&str]| {
        args.extend(extra.iter().map(|s| s.to_string()));
        audit(&args.iter().map(String::as_str).collect::<Vec<_>>())
    };

    let ok = run(base(&good, &at(EPOCH3_IAT + 60)), &["--operator-pin", &pin]);
    assert!(
        ok.status.success(),
        "{}",
        String::from_utf8_lossy(&ok.stderr)
    );
    assert_eq!(json(&ok)["submods"]["node"]["ear.status"], "affirming");

    // No pin: the quote verifies, but nothing ties its key to a TPM.
    let unpinned = run(base(&good, &at(EPOCH3_IAT + 60)), &[]);
    assert!(!unpinned.status.success());
    assert_eq!(json(&unpinned)["submods"]["node"]["ear.status"], "none");

    // A receipt two hours after the epoch: the evidence is stale.
    let stale = run(
        base(&good, &at(EPOCH3_IAT + 7200)),
        &["--operator-pin", &pin],
    );
    assert!(!stale.status.success());
    assert_eq!(json(&stale)["submods"]["node"]["ear.status"], "warning");

    // A reference expecting another PCR 16.
    let other = reference(dir.path(), &"00".repeat(32));
    let contested = run(
        base(&other, &at(EPOCH3_IAT + 60)),
        &["--operator-pin", &pin],
    );
    assert!(!contested.status.success());
    assert_eq!(
        json(&contested)["submods"]["node"]["ear.status"],
        "contraindicated"
    );

    // Bound to a different executor key: refused, nothing printed as a result.
    let mut wrong_key = base(&good, &at(EPOCH3_IAT + 60));
    wrong_key[6] = "00".repeat(32);
    let refused = run(wrong_key, &["--operator-pin", &pin]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("refused"));
}

struct Receipted {
    receipt: PathBuf,
    expectations: PathBuf,
}

fn receipt_naming(dir: &Path, platform: NodePlatform, issued_secs: u64) -> Receipted {
    let key = SigningKey::from_bytes(&[7; 32]);
    let digest = "a".repeat(64);
    let claim = ExecutionClaim {
        schema: ExecutionSchema::V1,
        pod_id: "pod-1".into(),
        source_commit: "commit".into(),
        source_tree: "tree".into(),
        gate: "tests".into(),
        program_digest: digest.clone(),
        architecture: "aarch64".into(),
        backend: Backend::Firecracker,
        uid_isolated: true,
        exit_code: Some(0),
        stdout_sha256: digest.clone(),
        stderr_sha256: digest.clone(),
        launch_hash: digest.clone(),
        environment_inputs_sha256: digest.clone(),
        environment_complete_sha256: digest.clone(),
        artifacts: Default::default(),
        node_platform: platform,
    };
    let issued = issued_secs * 1_000_000;
    let expected = RecordedExecution {
        pod_id: "pod-1".into(),
        source_commit: "commit".into(),
        source_tree: "tree".into(),
        gate: "tests".into(),
        program_digest: digest.clone(),
        architecture: "aarch64".into(),
        environment_inputs_sha256: digest,
        artifacts: Default::default(),
        session_id: "session".into(),
        issuer_kid: "executor".into(),
        verifying_key: key.verifying_key().to_bytes(),
        issued_not_before_micros: issued - 1,
        // Far enough out that "now" is inside the controller's window.
        issued_not_after_micros: u64::MAX / 2,
    };
    let receipt = Receipt::sign(
        Session {
            session_id: "session".into(),
            issuer_kid: "executor".into(),
            issued_at_micros: issued,
            parent_chain: Vec::new(),
        },
        vec![claim.to_projection().unwrap()],
        &key,
    );
    let out = Receipted {
        receipt: dir.join("receipt.json"),
        expectations: dir.join("expected.json"),
    };
    std::fs::write(&out.receipt, serde_json::to_vec(&receipt).unwrap()).unwrap();
    std::fs::write(&out.expectations, serde_json::to_vec(&expected).unwrap()).unwrap();
    out
}

fn evidence_platform(name: &str, epoch: u64) -> NodePlatform {
    let bytes = std::fs::read(fixture(name)).unwrap();
    NodePlatform::Evidence {
        evidence_sha256: hex::encode(Sha256::digest(&bytes)),
        epoch,
    }
}

#[test]
fn verify_execution_reports_authorization_and_platform_as_two_axes() {
    let dir = tempfile::tempdir().unwrap();
    let reference = reference(dir.path(), PCR16);
    let pin = format!("{SOURCE}={AK_PIN}");
    let evidence3 = fixture("node-evidence-swtpm-epoch3.json");
    let r = receipt_naming(
        dir.path(),
        evidence_platform("node-evidence-swtpm-epoch3.json", 3),
        EPOCH3_IAT + 120,
    );
    let verify = |extra: &[&str]| {
        let mut args = vec![
            "verify-execution".to_string(),
            "--receipt".into(),
            r.receipt.display().to_string(),
            "--expectations".into(),
            r.expectations.display().to_string(),
        ];
        args.extend(extra.iter().map(|s| s.to_string()));
        audit(&args.iter().map(String::as_str).collect::<Vec<_>>())
    };
    let ev = evidence3.display().to_string();
    let rf = reference.display().to_string();

    let attested = verify(&[
        "--node-evidence",
        &ev,
        "--node-reference",
        &rf,
        "--operator-pin",
        &pin,
        "--require-attested",
    ]);
    assert!(
        attested.status.success(),
        "{}",
        String::from_utf8_lossy(&attested.stderr)
    );
    let report = json(&attested);
    assert_eq!(report["execution_verified"], true);
    assert_eq!(
        report["node_platform"]["verdict"],
        "authorized_on_an_attested_node"
    );

    // The receipt names evidence nobody supplied: not appraised, said so.
    let unappraised = verify(&[]);
    assert!(unappraised.status.success());
    let report = json(&unappraised);
    assert!(report["node_platform"]["platform"]["not_appraised"].is_string());
    assert_eq!(
        report["node_platform"]["verdict"],
        "authorized_platform_not_attested"
    );
    assert!(!verify(&["--require-attested"]).status.success());

    // Another epoch's document is not the one the receipt names.
    let evidence4 = fixture("node-evidence-swtpm-epoch4.json")
        .display()
        .to_string();
    let swapped = verify(&[
        "--node-evidence",
        &evidence4,
        "--node-reference",
        &rf,
        "--operator-pin",
        &pin,
    ]);
    assert!(!swapped.status.success());
    assert!(String::from_utf8_lossy(&swapped.stderr).contains("is not the evidence document"));

    // Without the pin, authorization still verifies; the platform does not.
    let unpinned = verify(&["--node-evidence", &ev, "--node-reference", &rf]);
    assert!(unpinned.status.success());
    assert_eq!(
        json(&unpinned)["node_platform"]["verdict"],
        "authorized_platform_not_attested"
    );
}

#[test]
fn a_receipt_signed_long_after_its_epoch_is_not_attested() {
    let dir = tempfile::tempdir().unwrap();
    let reference = reference(dir.path(), PCR16);
    let r = receipt_naming(
        dir.path(),
        evidence_platform("node-evidence-swtpm-epoch3.json", 3),
        EPOCH3_IAT + 7200,
    );
    let out = audit(&[
        "verify-execution",
        "--receipt",
        &r.receipt.display().to_string(),
        "--expectations",
        &r.expectations.display().to_string(),
        "--node-evidence",
        &fixture("node-evidence-swtpm-epoch3.json")
            .display()
            .to_string(),
        "--node-reference",
        &reference.display().to_string(),
        "--operator-pin",
        &format!("{SOURCE}={AK_PIN}"),
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = json(&out);
    assert_eq!(
        report["node_platform"]["platform"]["tier"]["tier"],
        "expired"
    );
}

#[test]
fn an_unattested_receipt_is_never_upgraded_by_evidence_beside_it() {
    let dir = tempfile::tempdir().unwrap();
    let reference = reference(dir.path(), PCR16);
    let r = receipt_naming(
        dir.path(),
        NodePlatform::Unattested {
            reason: "no TPM".into(),
        },
        EPOCH3_IAT + 60,
    );
    let out = audit(&[
        "verify-execution",
        "--receipt",
        &r.receipt.display().to_string(),
        "--expectations",
        &r.expectations.display().to_string(),
        "--node-evidence",
        &fixture("node-evidence-swtpm-epoch3.json")
            .display()
            .to_string(),
        "--node-reference",
        &reference.display().to_string(),
        "--operator-pin",
        &format!("{SOURCE}={AK_PIN}"),
    ]);
    assert!(out.status.success());
    let report = json(&out);
    assert_eq!(report["node_platform"]["platform"]["tier"], "unattested");
    assert_eq!(report["node_platform"]["platform"]["reason"], "no TPM");
}

/// A software TPM is anchored only by `--allow-software-tpm-pin`, and labelled
/// `software_tpm`; the same fingerprint under `--operator-pin` anchors nothing,
/// so a verifier that asked for hardware never accepts a software TPM. The
/// claim is the fixture's own, rewritten: the anchor claim is not quoted, so
/// the quote still verifies and only the anchor decides.
#[test]
fn a_software_tpm_is_anchored_only_by_its_own_flag_and_labelled_so() {
    let dir = tempfile::tempdir().unwrap();
    let mut doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(fixture("node-evidence-swtpm-epoch3.json")).unwrap())
            .unwrap();
    doc["ak_anchor"] = serde_json::json!({ "software_tpm": { "source": SOURCE } });
    let evidence = dir.path().join("software-tpm-evidence.json");
    std::fs::write(&evidence, serde_json::to_vec(&doc).unwrap()).unwrap();
    let good = reference(dir.path(), PCR16);
    let pin = format!("{SOURCE}={AK_PIN}");
    let time = (EPOCH3_IAT + 60).to_string();
    let run = |extra: &[&str]| {
        let mut args = vec![
            "verify-node-evidence",
            "--evidence",
            evidence.to_str().unwrap(),
            "--reference",
            good.to_str().unwrap(),
            "--executor-ed25519",
            EXECUTOR,
            "--receipt-time",
            &time,
        ];
        args.extend_from_slice(extra);
        audit(&args)
    };

    let allowed = run(&["--allow-software-tpm-pin", &pin]);
    assert!(
        allowed.status.success(),
        "{}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    let ear = json(&allowed);
    assert_eq!(ear["submods"]["node"]["ear.status"], "affirming");
    assert_eq!(
        ear["submods"]["node"]["nucleus.appraisal"]["anchor"]["software_tpm"]["source"],
        SOURCE
    );

    let as_operator = run(&["--operator-pin", &pin]);
    assert!(!as_operator.status.success());
    assert_eq!(json(&as_operator)["submods"]["node"]["ear.status"], "none");

    // And the other way: the fixture's own operator claim is not anchored by
    // a software-TPM pin.
    let original = fixture("node-evidence-swtpm-epoch3.json");
    let operator_claim = audit(&[
        "verify-node-evidence",
        "--evidence",
        original.to_str().unwrap(),
        "--reference",
        good.to_str().unwrap(),
        "--executor-ed25519",
        EXECUTOR,
        "--receipt-time",
        &time,
        "--allow-software-tpm-pin",
        &pin,
    ]);
    assert!(!operator_claim.status.success());
    assert_eq!(
        json(&operator_claim)["submods"]["node"]["ear.status"],
        "none"
    );
}
