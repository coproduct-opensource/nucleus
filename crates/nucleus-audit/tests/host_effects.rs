//! Exercise the shipped command, with an independently supplied trust anchor.
use ed25519_dalek::{Signer, SigningKey};
use nucleus_spec::host_effect::{Authorization, SignedAuthorization, VERSION, signing_bytes};

#[test]
fn host_effect_command_verifies_a_pinned_authorization_and_rejects_a_guest_key() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("host-effects.jsonl");
    let host = SigningKey::from_bytes(&[91; 32]);
    let authorization = Authorization {
        version: VERSION,
        pod_id: "pod-a".into(),
        sequence: 1,
        effect_sha256: "ab".repeat(32),
        operation: "web_fetch".into(),
        subject: "https://upstream.invalid".into(),
        authorized_unix: 100,
        previous_record_sha256: String::new(),
    };
    let signature = hex::encode(
        host.sign(&signing_bytes(&authorization).unwrap())
            .to_bytes(),
    );
    let record = SignedAuthorization {
        authorization,
        signature,
    };
    std::fs::write(
        &log,
        format!("{}\n", serde_json::to_string(&record).unwrap()),
    )
    .unwrap();
    let run = |key: &SigningKey| {
        std::process::Command::new(env!("CARGO_BIN_EXE_nucleus-audit"))
            .arg("verify-host-effects")
            .arg("--log")
            .arg(&log)
            .args([
                "--pod",
                "pod-a",
                "--host-pubkey",
                &hex::encode(key.verifying_key().to_bytes()),
            ])
            .output()
            .unwrap()
    };
    let verified = run(&host);
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    let output = String::from_utf8(verified.stdout).unwrap();
    assert!(output.contains("Verified 1 host authorizations"));
    assert!(output.contains("not execution success"));
    let rejected = run(&SigningKey::from_bytes(&[92; 32]));
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("host signature does not verify"));
}
