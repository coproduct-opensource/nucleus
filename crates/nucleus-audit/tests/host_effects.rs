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

    use nucleus_spec::host_effect::{outcome, record_hash};
    let outcomes = dir.path().join("outcomes.jsonl");
    let claim = outcome::Outcome {
        version: outcome::VERSION,
        pod_id: "pod-a".into(),
        sequence: 1,
        authorization_record_sha256: record_hash(&record).unwrap(),
        observed_unix: 101,
        termination: outcome::Termination::Interrupted,
        response: None,
        previous_record_sha256: String::new(),
    };
    let signed = outcome::SignedOutcome {
        signature: hex::encode(
            host.sign(&outcome::signing_bytes(&claim).unwrap())
                .to_bytes(),
        ),
        outcome: claim,
    };
    let run_outcomes = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_nucleus-audit"))
            .arg("verify-host-effects")
            .arg("--log")
            .arg(&log)
            .arg("--outcomes")
            .arg(&outcomes)
            .args([
                "--pod",
                "pod-a",
                "--host-pubkey",
                &hex::encode(host.verifying_key().to_bytes()),
            ])
            .output()
            .unwrap()
    };
    std::fs::write(&outcomes, "").unwrap();
    let missing = run_outcomes();
    assert!(missing.status.success());
    assert!(
        String::from_utf8_lossy(&missing.stdout).contains("1 authorizations have unknown outcomes")
    );
    std::fs::write(
        &outcomes,
        format!("{}\n", serde_json::to_string(&signed).unwrap()),
    )
    .unwrap();
    let observed = run_outcomes();
    assert!(
        observed.status.success(),
        "{}",
        String::from_utf8_lossy(&observed.stderr)
    );
    assert!(
        String::from_utf8_lossy(&observed.stdout).contains("Verified 1 host transport outcomes")
    );
    let mut tampered = signed;
    tampered.outcome.termination = outcome::Termination::ResponseRead;
    std::fs::write(
        &outcomes,
        format!("{}\n", serde_json::to_string(&tampered).unwrap()),
    )
    .unwrap();
    assert!(!run_outcomes().status.success());
}
