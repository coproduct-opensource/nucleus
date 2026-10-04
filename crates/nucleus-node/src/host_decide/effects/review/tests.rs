use super::*;
use crate::upstreams::CallCharge;
use nucleus_spec::host_effect_approval::EffectRequest;
use sha2::{Digest, Sha256};
const NOW: u64 = 1000;
fn operator() -> Operator {
    Operator::authenticate("operator", "operator").unwrap()
}
fn metadata(body: &[u8]) -> EffectRequest {
    EffectRequest {
        require_approval: false,
        operation: "GitCommit".into(),
        upstream: "api".into(),
        url: "https://upstream.invalid/commit".into(),
        method: "POST".into(),
        credential_header: "authorization".into(),
        content_type: "application/json".into(),
        body_sha256: Sha256::digest(body).into(),
        body_bytes: body.len() as u64,
        call_charge_micro_usd: Some(0),
    }
}
fn pending(state: &mut PodPolicy, body: &[u8]) -> (ArgsDigest, EffectRequest, uuid::Uuid) {
    let request = metadata(body);
    let digest = ArgsDigest::new(request.digest().unwrap());
    assert!(
        state
            .preflight_effect(
                digest,
                portcullis::Operation::GitCommit,
                &request.url,
                NOW,
                CallCharge::free(),
                false
            )
            .is_err()
    );
    let id = state
        .list_effect_approvals(operator(), NOW)
        .into_iter()
        .find(|a| a.effect_sha256 == hex::encode(digest.as_bytes()))
        .unwrap()
        .id;
    (digest, request, id)
}
fn policy() -> crate::host_decide::SharedPodPolicy {
    let mut lattice = portcullis::PermissionLattice::permissive();
    lattice.obligations.insert(portcullis::Operation::GitCommit);
    crate::host_decide::test_policy(lattice)
}
#[test]
fn substituted_payload_is_refused_and_expiry_removes_the_retained_review() {
    let shared = policy();
    let mut state = shared.lock().unwrap();
    let (digest, request, id) = pending(&mut state, b"first");
    assert!(state.attach_review(digest, request, b"other", NOW).is_err());
    assert!(
        state
            .settle_effect_approval(operator(), id, true, NOW)
            .is_err()
    );
    let (digest, request, id) = pending(&mut state, b"valid");
    state.attach_review(digest, request, b"valid", NOW).unwrap();
    assert!(state.effect_review(operator(), id, NOW).is_ok());
    assert!(
        state
            .effect_review(operator(), id, NOW + super::super::APPROVAL_TTL)
            .is_err()
    );
    assert!(state.approvals.entries.is_empty());
}
#[test]
fn aggregate_payload_cap_refuses_more_data_and_deduplicates_retries() {
    let shared = policy();
    let mut state = shared.lock().unwrap();
    let body = vec![7; MAX_REVIEW_BYTES as usize];
    let (digest, request, id) = pending(&mut state, &body);
    state
        .attach_review(digest, request.clone(), &body, NOW)
        .unwrap();
    state.attach_review(digest, request, &body, NOW).unwrap();
    assert!(state.approvals.entries[&id].review.is_some());
    let (digest, request, id) = pending(&mut state, b"x");
    assert!(state.attach_review(digest, request, b"x", NOW).is_err());
    assert!(
        state
            .settle_effect_approval(operator(), id, true, NOW)
            .is_err()
    );
}
