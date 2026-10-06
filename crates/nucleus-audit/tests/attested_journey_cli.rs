//! The audit CLI over the attested journey re-run (2026-10-06, release v2.5.0,
//! an x86 Shielded VM whose node federates): the signed execution receipt the
//! run produced, the epoch-8 evidence document it names, and the release's
//! published reference manifest (#3276, #3277).
//!
//! The expectations are the ones `prepare-execution` wrote for the run, with
//! the controller's issuance window widened so the test does not expire.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const EXECUTOR: &str = "da9c0ad013b6f16dcf1289259941de450b9158d0d864bd992af9ed35f5e601a1";
const JWKS_SHA256: &str = "104818fd20043431085e1f81242214ca8150f3f7534526f8b26b70d61460e4f3";
const PIN: &str = "gcp-shielded-vm-identity:nucleus-attest-node-202610062100=0cbb90024acd17ca34b8937d4bc273621ee8f9af2f5fba7eb3811bc38051b68f";
const IAT: i64 = 1_791_322_322;

fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
        .display()
        .to_string()
}

fn audit(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nucleus-audit"))
        .args(args)
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

/// The published v2.5.0 manifest, and the same manifest with the IMA scope
/// `release-reference-manifest emit` now writes for the default install dir.
fn references(dir: &Path) -> (String, String) {
    let published = fixture("release-2.5.0-x86_64.node-reference.json");
    let mut m: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&published).unwrap()).unwrap();
    m["reference-values"]["ima"]["required"]["scope"] =
        serde_json::json!({ "path_prefixes": ["/usr/local/bin"] });
    let scoped: PathBuf = dir.join("scoped.node-reference.json");
    std::fs::write(&scoped, serde_json::to_vec(&m).unwrap()).unwrap();
    (published, scoped.display().to_string())
}

fn ima_not_in_scope(appraisal_ear: &serde_json::Value) -> usize {
    appraisal_ear["submods"]["node"]["nucleus.appraisal"]["ima_not_in_scope"]
        .as_array()
        .map_or(0, Vec::len)
}

#[test]
fn standalone_a_federating_node_is_refused_by_name_then_verifies_with_the_digest() {
    let dir = tempfile::tempdir().unwrap();
    let (published, scoped) = references(dir.path());
    let evidence = fixture("attested-journey-epoch8-evidence.json");
    let receipt_time = (IAT + 111).to_string();
    let run = |reference: &str, extra: &[&str]| {
        let mut args = vec![
            "verify-node-evidence",
            "--evidence",
            &evidence,
            "--reference",
            reference,
            "--executor-ed25519",
            EXECUTOR,
            "--receipt-time",
            &receipt_time,
            "--operator-pin",
            PIN,
        ];
        args.extend_from_slice(extra);
        audit(&args)
    };

    // The default expects no federation: refused, and the refusal names the
    // digest the evidence binds and the flag that states it.
    let refused = run(&scoped, &[]);
    assert!(!refused.status.success());
    let stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        stderr.contains(&format!("binds federation JWKS sha256 {JWKS_SHA256}")),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!("--federation {JWKS_SHA256}")),
        "{stderr}"
    );

    // Stated: the release manifest alone affirms, with the host's kernel
    // modules listed as outside its scope.
    let attested = run(&scoped, &["--federation", JWKS_SHA256]);
    assert!(
        attested.status.success(),
        "{}",
        String::from_utf8_lossy(&attested.stderr)
    );
    let ear = stdout_json(&attested);
    assert_eq!(ear["submods"]["node"]["ear.status"], "affirming");
    assert_eq!(ima_not_in_scope(&ear), 64);

    // The published (unscoped) v2.5.0 manifest contests the same evidence.
    let contested = run(&published, &["--federation", JWKS_SHA256]);
    assert!(!contested.status.success());
    let ear = stdout_json(&contested);
    assert_eq!(ear["submods"]["node"]["ear.status"], "contraindicated");
    assert_eq!(ima_not_in_scope(&ear), 0);
}

#[test]
fn through_the_receipt_the_federation_set_is_derived_and_no_flag_is_needed() {
    let dir = tempfile::tempdir().unwrap();
    let (_, scoped) = references(dir.path());
    let expectations = dir.path().join("expected.json");
    let verifying_key: Vec<u8> = hex::decode(EXECUTOR).unwrap();
    std::fs::write(
        &expectations,
        serde_json::to_vec(&serde_json::json!({
            "pod_id": "84bcc0d5-c04e-4cbb-a34b-f90d0565dc0e",
            "source_commit": "",
            "source_tree": "",
            "gate": "",
            "program_digest": "29f0fc219e8dea0a48565ccf12b49878e97c55f146b0359e699d2ba3fb52532b",
            "architecture": "x86_64",
            "environment_inputs_sha256": "2ac0de4e5ca700253c10d0a5579e86a66ab184358b3fe945cd5a46caf26149e9",
            "artifacts": {},
            "session_id": "84bcc0d5-c04e-4cbb-a34b-f90d0565dc0e",
            "issuer_kid": "nucleus-executor/653fa23a5119fe27",
            "verifying_key": verifying_key,
            "issued_not_before_micros": 1_791_321_625_000_000_u64,
            "issued_not_after_micros": u64::MAX / 2,
        }))
        .unwrap(),
    )
    .unwrap();
    let out = audit(&[
        "verify-execution",
        "--receipt",
        &fixture("attested-journey-receipt.json"),
        "--expectations",
        &expectations.display().to_string(),
        "--node-evidence",
        &fixture("attested-journey-epoch8-evidence.json"),
        "--node-reference",
        &scoped,
        "--operator-pin",
        PIN,
        "--require-attested",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let report = stdout_json(&out);
    assert_eq!(report["execution_verified"], true);
    assert_eq!(
        report["node_platform"]["verdict"],
        "authorized_on_an_attested_node"
    );
    let ear = &report["node_platform"]["platform"]["ear"];
    assert_eq!(ima_not_in_scope(ear), 64);
    assert_eq!(
        ear["submods"]["node"]["nucleus.appraisal"]["binding"]["federation"]["jwks_sha256"],
        JWKS_SHA256
    );
}
