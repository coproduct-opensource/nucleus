use ed25519_dalek::SigningKey;
use nucleus_ci_verdict::verify::{ExpectedRun, VerificationError, verify};
use nucleus_ci_verdict::{CiVerdict, Conclusion};
use nucleus_receipt::{Receipt, Session};

fn claim() -> CiVerdict {
    CiVerdict {
        action_key: "action".into(),
        context: "nucleus/build".into(),
        tree: "tree".into(),
        conclusion: Conclusion::Success,
        exit_status: 0,
        log_digest: "log".into(),
        pod_id: "pod-1".into(),
        certificate: None,
    }
}

fn sign(claim: &CiVerdict, key: &SigningKey, issued: u64) -> Receipt {
    Receipt::sign(
        Session {
            session_id: "node-1".into(),
            issuer_kid: "trusted".into(),
            issued_at_micros: issued,
            parent_chain: vec![],
        },
        vec![claim.to_projection()],
        key,
    )
}

fn expected(key: &[u8; 32]) -> ExpectedRun<'_> {
    ExpectedRun {
        action_key: "action",
        context: "nucleus/build",
        tree: "tree",
        pod_id: "pod-1",
        session_id: "node-1",
        issuer_kid: "trusted",
        verifying_key: key,
        issued_not_before_micros: 100,
        issued_not_after_micros: 200,
    }
}

#[test]
fn authenticated_outcomes_remain_distinct() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    for (conclusion, status) in [
        (Conclusion::Success, 0),
        (Conclusion::Failure, 1),
        (Conclusion::CouldNotLook, -1),
    ] {
        let mut claim = claim();
        claim.conclusion = conclusion;
        claim.exit_status = status;
        let checked = verify(&sign(&claim, &key, 150), &expected(&public)).unwrap();
        assert_eq!(checked.verdict().conclusion, conclusion);
        assert_eq!(checked.into_verdict(200).unwrap().exit_status, status);
    }
}

#[test]
fn a_verified_verdict_expires_before_delayed_publication() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    let checked = verify(&sign(&claim(), &key, 150), &expected(&public)).unwrap();
    assert_eq!(
        checked.into_verdict(201).unwrap_err(),
        VerificationError::OutsideWindow
    );
}

#[test]
fn another_signer_cannot_claim_the_trusted_key_id() {
    let public = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
    let attacker = SigningKey::from_bytes(&[8; 32]);
    assert!(matches!(
        verify(&sign(&claim(), &attacker, 150), &expected(&public)),
        Err(VerificationError::Signature(_))
    ));
}

#[test]
fn signed_claims_for_another_run_are_refused() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    for field in ["action_key", "context", "tree", "pod_id"] {
        let mut claim = claim();
        match field {
            "action_key" => claim.action_key = "other".into(),
            "context" => claim.context = "other".into(),
            "tree" => claim.tree = "other".into(),
            "pod_id" => claim.pod_id = "other".into(),
            _ => unreachable!(),
        }
        assert_eq!(
            verify(&sign(&claim, &key, 150), &expected(&public)).unwrap_err(),
            VerificationError::Binding(field)
        );
    }
}

#[test]
fn stale_and_future_claims_cannot_answer_this_attempt() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    for issued in [99, 201] {
        assert_eq!(
            verify(&sign(&claim(), &key, issued), &expected(&public)).unwrap_err(),
            VerificationError::OutsideWindow
        );
    }
}

#[test]
fn a_signed_success_with_a_failing_exit_status_is_refused() {
    let key = SigningKey::from_bytes(&[7; 32]);
    let public = key.verifying_key().to_bytes();
    let mut claim = claim();
    claim.exit_status = 1;
    assert_eq!(
        verify(&sign(&claim, &key, 150), &expected(&public)).unwrap_err(),
        VerificationError::InconsistentOutcome
    );
}
