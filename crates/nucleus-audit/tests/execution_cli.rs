use std::collections::BTreeMap;
use std::process::Command;

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use nucleus_ci_verdict::execution::{
    ArtifactIdentity, Backend, ExecutionClaim, ExecutionSchema, RecordedExecution,
};
use nucleus_receipt::{Receipt, Session};
use sha2::{Digest, Sha256};

#[test]
fn collected_bundle_and_receipt_verify_without_turning_nonzero_exit_into_success() {
    let dir = tempfile::tempdir().unwrap();
    let key = SigningKey::from_bytes(&[7; 32]);
    let digest = "a".repeat(64);
    let artifact = b"test output\0\xff";
    let paths = BTreeMap::from([("tests".into(), "test-results.bin".into())]);
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
        exit_code: Some(7),
        stdout_sha256: digest.clone(),
        stderr_sha256: digest.clone(),
        launch_hash: digest.clone(),
        environment_inputs_sha256: digest.clone(),
        environment_complete_sha256: digest.clone(),
        artifacts: BTreeMap::from([(
            "tests".into(),
            ArtifactIdentity {
                path: "test-results.bin".into(),
                sha256: hex::encode(Sha256::digest(artifact)),
                size: artifact.len() as u64,
            },
        )]),
    };
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap();
    let expected = RecordedExecution {
        pod_id: "pod-1".into(),
        source_commit: "commit".into(),
        source_tree: "tree".into(),
        gate: "tests".into(),
        program_digest: digest.clone(),
        architecture: "aarch64".into(),
        environment_inputs_sha256: digest,
        artifacts: paths,
        session_id: "session".into(),
        issuer_kid: "executor".into(),
        verifying_key: key.verifying_key().to_bytes(),
        issued_not_before_micros: now - 1,
        issued_not_after_micros: now + 60_000_000,
    };
    let receipt = Receipt::sign(
        Session {
            session_id: "session".into(),
            issuer_kid: "executor".into(),
            issued_at_micros: now,
            parent_chain: Vec::new(),
        },
        vec![claim.to_projection().unwrap()],
        &key,
    );
    let expectations = dir.path().join("expected.json");
    std::fs::write(&expectations, serde_json::to_vec(&expected).unwrap()).unwrap();
    for (command, flag, document, count) in [
        (
            "verify-execution",
            "--receipt",
            serde_json::to_value(&receipt).unwrap(),
            serde_json::Value::Null,
        ),
        (
            "verify-artifacts",
            "--bundle",
            serde_json::json!({"receipt":receipt,"artifacts":{"tests":base64::engine::general_purpose::STANDARD.encode(artifact)}}),
            serde_json::json!(1),
        ),
    ] {
        let input = dir.path().join("input.json");
        std::fs::write(&input, serde_json::to_vec(&document).unwrap()).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_nucleus-audit"))
            .arg(command)
            .arg(flag)
            .arg(&input)
            .arg("--expectations")
            .arg(&expectations)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["execution_verified"], true);
        assert_eq!(report["artifact_bytes_verified"], count);
        assert_eq!(report["claim"]["exit_code"], 7);
        if command == "verify-artifacts" {
            let destination = dir.path().join("verified-files");
            let export = || {
                Command::new(env!("CARGO_BIN_EXE_nucleus-audit"))
                    .args(["verify-artifacts", "--bundle"])
                    .arg(&input)
                    .arg("--expectations")
                    .arg(&expectations)
                    .arg("--output-dir")
                    .arg(&destination)
                    .output()
                    .unwrap()
            };
            let output = export();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(std::fs::read(destination.join("tests")).unwrap(), artifact);
            assert!(!destination.join("test-results.bin").exists());
            let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(report["claim"]["exit_code"], 7);
            assert_eq!(report["artifacts_directory"], destination.to_str().unwrap());
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                for path in [&destination, &destination.join("tests")] {
                    assert_eq!(
                        std::fs::metadata(path).unwrap().permissions().mode() & 0o077,
                        0
                    );
                }
            }
            std::fs::write(destination.join("tests"), b"retained local note").unwrap();
            let repeated = export();
            assert!(!repeated.status.success());
            assert!(String::from_utf8_lossy(&repeated.stderr).contains("must not exist"));
            assert_eq!(
                std::fs::read(destination.join("tests")).unwrap(),
                b"retained local note"
            );
        }
    }
}
