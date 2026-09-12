use ed25519_dalek::SigningKey;
use nucleus_ci_verdict::execution::{
    Backend, ExecutionClaim, ExecutionError, ExecutionSchema, ExpectedExecution, verify_execution,
};
use nucleus_receipt::{Projection, Receipt, Session};

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn claim() -> ExecutionClaim {
    ExecutionClaim {
        schema: ExecutionSchema::V1,
        pod_id: "pod-1".into(),
        program_digest: DIGEST.into(),
        architecture: "x86_64".into(),
        backend: Backend::Firecracker,
        uid_isolated: true,
        exit_code: Some(0),
        stdout_sha256: DIGEST.into(),
        stderr_sha256: DIGEST.into(),
        launch_hash: DIGEST.into(),
        environment_inputs_sha256: DIGEST.into(),
        environment_complete_sha256: DIGEST.into(),
    }
}

fn sign_body(body: serde_json::Value, key: &SigningKey, issued: u64) -> Receipt {
    Receipt::sign(
        Session {
            session_id: "pod-1".into(),
            issuer_kid: "executor-1".into(),
            issued_at_micros: issued,
            parent_chain: vec![],
        },
        vec![Projection::Ci(body)],
        key,
    )
}

fn sign(claim: &ExecutionClaim, key: &SigningKey) -> Receipt {
    sign_body(serde_json::to_value(claim).unwrap(), key, 150)
}

fn expected(key: &[u8; 32]) -> ExpectedExecution<'_> {
    ExpectedExecution {
        pod_id: "pod-1",
        program_digest: DIGEST,
        architecture: "x86_64",
        environment_inputs_sha256: DIGEST,
        session_id: "pod-1",
        issuer_kid: "executor-1",
        verifying_key: key,
        issued_not_before_micros: 100,
        issued_not_after_micros: 200,
    }
}

#[test]
fn authenticated_execution_preserves_failure_and_signal() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    for exit in [Some(0), Some(23), None] {
        let mut claim = claim();
        claim.exit_code = exit;
        let verified = verify_execution(&sign(&claim, &key), &expected(&public)).unwrap();
        assert_eq!(verified.into_claim(200).unwrap().exit_code, exit);
    }
}

#[test]
fn verified_execution_expires_before_delayed_consumption() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    let verified = verify_execution(&sign(&claim(), &key), &expected(&public)).unwrap();
    assert_eq!(
        verified.into_claim(201).unwrap_err(),
        ExecutionError::OutsideWindow
    );
}

#[test]
fn every_serialized_execution_field_is_inside_the_signature() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    let body = serde_json::to_value(claim()).unwrap();
    for field in body.as_object().unwrap().keys() {
        let mut tampered = body.clone();
        tampered[field] = serde_json::json!("tampered");
        let mut receipt = sign(&claim(), &key);
        receipt.projections = vec![Projection::Ci(tampered)];
        assert!(
            matches!(
                verify_execution(&receipt, &expected(&public)),
                Err(ExecutionError::Authentication(_))
            ),
            "unsigned field: {field}"
        );
    }
}

#[test]
fn signed_execution_for_another_pod_program_or_architecture_is_refused() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    for field in [
        "pod_id",
        "program_digest",
        "architecture",
        "environment_inputs_sha256",
    ] {
        let mut body = serde_json::to_value(claim()).unwrap();
        body[field] = serde_json::json!("another");
        assert_eq!(
            verify_execution(&sign_body(body, &key, 150), &expected(&public)).unwrap_err(),
            ExecutionError::Binding(field)
        );
    }
}

#[test]
fn signed_local_container_and_unconfined_guest_are_not_microvm_evidence() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    for (backend, uid_isolated) in [
        (Backend::Local, true),
        (Backend::Container, true),
        (Backend::Firecracker, false),
    ] {
        let mut claim = claim();
        claim.backend = backend;
        claim.uid_isolated = uid_isolated;
        assert_eq!(
            verify_execution(&sign(&claim, &key), &expected(&public)).unwrap_err(),
            ExecutionError::NotProtectedMicroVm
        );
    }
}

#[test]
fn signer_and_issuance_window_are_independent_expectations() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    let impostor = SigningKey::from_bytes(&[8; 32]);
    assert!(matches!(
        verify_execution(&sign(&claim(), &impostor), &expected(&public)),
        Err(ExecutionError::Authentication(_))
    ));
    for issued in [99, 201] {
        let receipt = sign_body(serde_json::to_value(claim()).unwrap(), &key, issued);
        assert_eq!(
            verify_execution(&receipt, &expected(&public)).unwrap_err(),
            ExecutionError::OutsideWindow
        );
    }
}

#[test]
fn unknown_schema_duplicate_body_and_missing_hash_are_refused() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    let mut body = serde_json::to_value(claim()).unwrap();
    body["schema"] = serde_json::json!("nucleus.execution.future");
    assert!(matches!(
        verify_execution(&sign_body(body, &key, 150), &expected(&public)),
        Err(ExecutionError::Body(_))
    ));
    let signed = sign(&claim(), &key);
    let duplicate = Receipt::sign(
        signed.session,
        vec![
            claim().to_projection().unwrap(),
            claim().to_projection().unwrap(),
        ],
        &key,
    );
    assert!(matches!(
        verify_execution(&duplicate, &expected(&public)),
        Err(ExecutionError::Body(_))
    ));
    let mut no_hash = claim();
    no_hash.stdout_sha256.clear();
    assert_eq!(
        verify_execution(&sign(&no_hash, &key), &expected(&public)).unwrap_err(),
        ExecutionError::InvalidDigest("stdout_sha256")
    );
}
