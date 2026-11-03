use ed25519_dalek::SigningKey;
use nucleus_ci_verdict::execution::{
    Backend, ExecutionClaim, ExecutionError, ExecutionSchema, ExpectedExecution,
    INSECURE_SHARED_UID_KID_PREFIX, NodePlatform, SandboxTier, verify_execution,
};
use nucleus_receipt::{Projection, Receipt, Session};

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn raw_logs_must_match_each_signed_stream_including_empty_and_non_utf8() {
    use sha2::{Digest, Sha256};
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    let stdout = b"raw\0\xff\nlast".to_vec();
    let stderr = Vec::new();
    let mut claim = claim();
    claim.exit_code = Some(23);
    claim.stdout_sha256 = hex::encode(Sha256::digest(&stdout));
    claim.stderr_sha256 = hex::encode(Sha256::digest(&stderr));
    let receipt = sign(&claim, &key);
    let execution = verify_execution(&receipt, &expected(&public)).unwrap();
    assert!(execution.verify_logs(Vec::new(), stderr.clone()).is_err());
    assert!(
        execution
            .verify_logs(stdout.clone(), b"injected".to_vec())
            .is_err()
    );
    assert!(
        execution
            .verify_logs(stderr.clone(), stdout.clone())
            .is_err()
    );
    let logs = execution
        .verify_logs(stdout.clone(), stderr.clone())
        .unwrap();
    assert_eq!(logs.stdout(), stdout);
    assert_eq!(logs.stderr(), stderr);
    assert_eq!(
        logs.into_parts(200).unwrap(),
        (stdout.clone(), stderr.clone())
    );
    let expired_logs = execution.verify_logs(stdout, stderr).unwrap();
    assert_eq!(
        expired_logs.into_parts(201).unwrap_err(),
        ExecutionError::OutsideWindow
    );
    assert_eq!(
        execution.into_claim(201).unwrap_err(),
        ExecutionError::OutsideWindow
    );
}
static NO_ARTIFACTS: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();

#[test]
fn recorded_controller_expectations_preserve_bindings_and_refuse_unknown_fields() {
    use nucleus_ci_verdict::execution::RecordedExecution;
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    let wire = serde_json::to_value(expected(&public)).unwrap();
    let mut record: RecordedExecution = serde_json::from_value(wire.clone()).unwrap();
    let receipt = sign(&claim(), &key);
    assert!(verify_execution(&receipt, &record.as_expected()).is_ok());
    record.source_commit = "another-source".into();
    assert!(verify_execution(&receipt, &record.as_expected()).is_err());
    let mut unknown = wire;
    unknown["unexpected_trust_override"] = serde_json::json!(true);
    assert!(serde_json::from_value::<RecordedExecution>(unknown).is_err());
}

#[test]
fn artifact_bytes_names_paths_and_consumption_deadline_are_checked() {
    use nucleus_ci_verdict::execution::{ArtifactIdentity, verify_artifacts};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    let paths = BTreeMap::from([("binary".into(), "target/nucleus-node".into())]);
    let mut expected = expected(&public);
    expected.artifacts = &paths;
    let data = b"binary\0\xff".to_vec();
    let bytes = BTreeMap::from([("binary".into(), data.clone())]);
    let mut claim = claim();
    claim.artifacts.insert(
        "binary".into(),
        ArtifactIdentity {
            path: "target/nucleus-node".into(),
            sha256: hex::encode(Sha256::digest(&data)),
            size: data.len() as u64,
        },
    );
    let receipt = sign(&claim, &key);
    let valid = verify_artifacts(&receipt, &expected, bytes.clone()).unwrap();
    assert_eq!(valid.into_parts(200).unwrap().1, bytes);
    assert_eq!(
        verify_artifacts(&receipt, &expected, bytes.clone())
            .unwrap()
            .into_parts(201)
            .unwrap_err(),
        ExecutionError::OutsideWindow
    );
    let changed = BTreeMap::from([("binary".into(), b"altered\0".to_vec())]);
    assert!(verify_artifacts(&receipt, &expected, changed).is_err());
    assert!(verify_artifacts(&receipt, &expected, BTreeMap::new()).is_err());
    let renamed = BTreeMap::from([("other".into(), data)]);
    assert!(verify_artifacts(&receipt, &expected, renamed).is_err());
    claim.artifacts.get_mut("binary").unwrap().path = "another/source".into();
    assert!(verify_artifacts(&sign(&claim, &key), &expected, bytes).is_err());
}

fn claim() -> ExecutionClaim {
    ExecutionClaim {
        schema: ExecutionSchema::V1,
        pod_id: "pod-1".into(),
        source_commit: "commit-1".into(),
        source_tree: "tree-1".into(),
        gate: "gate-1".into(),
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
        artifacts: Default::default(),
        node_platform: NodePlatform::Evidence {
            evidence_sha256: DIGEST.into(),
            epoch: 4,
        },
        sandbox_tier: SandboxTier::Driver,
    }
}

/// C0: a bare-tier node's key is readable by its workloads, so its evidence is
/// refused by name, even pinned, even claiming a protected microVM, and even
/// when everything else about the claim binds.
#[test]
fn insecure_tier_evidence_is_refused_by_its_key_and_by_its_declaration() {
    let key = SigningKey::from_bytes(&[9; 32]);
    let public = key.verifying_key().to_bytes();
    let insecure_kid = format!("{INSECURE_SHARED_UID_KID_PREFIX}0011223344556677");

    // The node's own declaration, under an otherwise ordinary kid.
    let mut declared = claim();
    declared.sandbox_tier = SandboxTier::InsecureSharedUid;
    assert_eq!(
        verify_execution(&sign(&declared, &key), &expected(&public)).unwrap_err(),
        ExecutionError::InsecureSharedUid
    );

    // The insecure kid, pinned by a controller that took the node's
    // admission at its word, over a forged Firecracker / uid-isolated claim
    // that omits the declaration.
    let forged = claim();
    assert_eq!(forged.backend, Backend::Firecracker);
    assert!(forged.uid_isolated);
    let receipt = sign_body_as(serde_json::to_value(&forged).unwrap(), &key, &insecure_kid);
    let mut pinned = expected(&public);
    pinned.issuer_kid = &insecure_kid;
    assert_eq!(
        verify_execution(&receipt, &pinned).unwrap_err(),
        ExecutionError::InsecureSharedUid
    );
    // And the same receipt against an ordinary pin is refused by name too,
    // not merely as a kid mismatch.
    assert_eq!(
        verify_execution(&receipt, &expected(&public)).unwrap_err(),
        ExecutionError::InsecureSharedUid
    );

    // Control: the identical claim under an ordinary kid verifies, so the
    // refusals above are the tier's and nothing else's.
    assert!(verify_execution(&sign(&forged, &key), &expected(&public)).is_ok());
}

/// The declaration is on the wire only when it says something, so every
/// receipt from a separating driver is byte-identical to before the field,
/// and a verifier predating it refuses an insecure claim as an unknown field.
#[test]
fn only_the_insecure_declaration_is_serialized() {
    let body = serde_json::to_value(claim()).unwrap();
    assert!(body.get("sandbox_tier").is_none());
    let mut insecure = claim();
    insecure.sandbox_tier = SandboxTier::InsecureSharedUid;
    let body = serde_json::to_value(&insecure).unwrap();
    assert_eq!(body["sandbox_tier"], "insecure-shared-uid");
    let back: ExecutionClaim = serde_json::from_value(body).unwrap();
    assert_eq!(back.sandbox_tier, SandboxTier::InsecureSharedUid);
}

fn sign_body_as(body: serde_json::Value, key: &SigningKey, kid: &str) -> Receipt {
    Receipt::sign(
        Session {
            session_id: "pod-1".into(),
            issuer_kid: kid.into(),
            issued_at_micros: 150,
            parent_chain: vec![],
        },
        vec![Projection::Ci(body)],
        key,
    )
}

#[test]
fn the_node_platform_is_signed_and_reported_not_required() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    let verified = verify_execution(&sign(&claim(), &key), &expected(&public)).unwrap();
    assert_eq!(
        verified.claim().node_platform,
        NodePlatform::Evidence {
            evidence_sha256: DIGEST.into(),
            epoch: 4
        }
    );
    let mut unattested = claim();
    unattested.node_platform = NodePlatform::Unattested {
        reason: "no TPM".into(),
    };
    assert!(verify_execution(&sign(&unattested, &key), &expected(&public)).is_ok());
}

#[test]
fn a_malformed_evidence_digest_is_refused() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    let mut c = claim();
    c.node_platform = NodePlatform::Evidence {
        evidence_sha256: "not-a-digest".into(),
        epoch: 1,
    };
    assert_eq!(
        verify_execution(&sign(&c, &key), &expected(&public)).unwrap_err(),
        ExecutionError::InvalidDigest("node_platform.evidence_sha256")
    );
}

#[test]
fn a_receipt_from_before_node_evidence_reads_as_unattested() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    let mut body = serde_json::to_value(claim()).unwrap();
    body.as_object_mut().unwrap().remove("node_platform");
    let verified = verify_execution(&sign_body(body, &key, 150), &expected(&public)).unwrap();
    assert_eq!(verified.claim().node_platform, NodePlatform::not_recorded());
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
        source_commit: "commit-1",
        source_tree: "tree-1",
        gate: "gate-1",
        program_digest: DIGEST,
        architecture: "x86_64",
        environment_inputs_sha256: DIGEST,
        artifacts: &NO_ARTIFACTS,
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

/// C2: a separated bare-tier node signs with its ordinary key and says
/// `separated-local`. That is a host process at a subordinate uid, not a
/// microVM, so a verifier that requires a protected microVM refuses it by
/// that declaration, even over a claim that pairs it with
/// `backend = firecracker` and `uid_isolated`; and the declaration is on the
/// wire, so a verifier predating it refuses it as an unknown field.
#[test]
fn separated_local_evidence_never_passes_as_a_microvm() {
    let key = SigningKey::from_bytes(&[9; 32]);
    let public = key.verifying_key().to_bytes();
    let mut separated = claim();
    separated.sandbox_tier = SandboxTier::SeparatedLocal;
    assert_eq!(separated.backend, Backend::Firecracker);
    assert!(separated.uid_isolated);
    assert_eq!(
        verify_execution(&sign(&separated, &key), &expected(&public)).unwrap_err(),
        ExecutionError::NotProtectedMicroVm
    );
    let body = serde_json::to_value(&separated).unwrap();
    assert_eq!(body["sandbox_tier"], "separated-local");
    let back: ExecutionClaim = serde_json::from_value(body).unwrap();
    assert_eq!(back.sandbox_tier, SandboxTier::SeparatedLocal);
    // Control: the same claim without the declaration verifies.
    assert!(verify_execution(&sign(&claim(), &key), &expected(&public)).is_ok());
}
