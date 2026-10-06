//! A push after a model call, in ONE pod (#3255): the operator's action-bound
//! approval is the declassification of that one request.
//!
//! Before #3255 the host refused a push from a pod that had received any
//! upstream response (`flow_refused`), with no exit, so a coding journey —
//! model output becomes a pushed commit — could not finish in one pod. The
//! flow rule is unchanged; it now has a governed exit (APPA, "Recoverable
//! Information-Flow Control for Real-World LLM Agents", arXiv 2607.24625):
//! the push is HELD, an approval bound to its digest releases exactly that
//! request once, and the host's signed record names the approval and the
//! labels it declassified.
use super::*;
use nucleus_spec::host_effect::{self, SignedAuthorization};

const SIGNING: [u8; 32] = [59; 32];

/// One pod that holds a model API and the git remote, with its host evidence
/// on disk, so the signed records are the ones a stranger would verify.
async fn one_pod(policy: PermissionLattice) -> (Pod, Hits) {
    let (base, hits) = remote().await;
    let (model, _) = super::super::upstream().await;
    let mut pod = declared(&base, policy.clone());
    pod.credentials = PodCredentials::static_only({
        let mut store = CredentialStore::new();
        for name in ["git-remote", "model-api"] {
            store.insert(name, Credential::new(TOKEN));
        }
        store
    });
    pod.upstreams
        .push(RegistryEntry::env(nucleus_spec::CredentialedEgressSpec {
            name: "model-api".into(),
            upstream: model,
            credential_env: "LLM_API_TOKEN".into(),
            header: "authorization".into(),
            value_prefix: "Bearer ".into(),
            effects: nucleus_spec::EffectTable::unclassified(),
        }));
    let evidence = crate::host_decide::evidence::Evidence::create(
        uuid::Uuid::new_v4(),
        pod.dir.path(),
        Arc::new(ed25519_dalek::SigningKey::from_bytes(&SIGNING)),
    )
    .unwrap();
    pod.host_policy =
        crate::host_decide::PodPolicy::new(portcullis::kernel::Kernel::new(policy), evidence);
    (pod, hits)
}

/// The model call: an upstream response, which taints the host's view of the
/// pod before a byte of it reaches the guest.
async fn model_call(pod: &Pod) {
    let heard = drive(pod, &open("model-api", "model-call"), b"{}").await;
    assert!(heard.head.granted, "{:?}", heard.head);
}

fn receive_pack(nonce: &str) -> StreamRequest {
    let mut send = git_open(
        EgressMethod::Post,
        "org/repo.git/git-receive-pack",
        None,
        nonce,
    );
    send.content_type = "application/x-git-receive-pack-request".into();
    send
}

/// The host's signed authorizations, each verified under the pinned key.
fn records(pod: &Pod) -> Vec<SignedAuthorization> {
    let key = ed25519_dalek::SigningKey::from_bytes(&SIGNING).verifying_key();
    std::fs::read_to_string(pod.dir.path().join(host_effect::LOG_FILE))
        .unwrap()
        .lines()
        .map(|line| {
            let record: SignedAuthorization = serde_json::from_str(line).unwrap();
            let signature =
                ed25519_dalek::Signature::from_slice(&hex::decode(&record.signature).unwrap())
                    .unwrap();
            key.verify_strict(
                &host_effect::signing_bytes(&record.authorization).unwrap(),
                &signature,
            )
            .unwrap();
            record
        })
        .collect()
}

/// The operator's review of a held push says it is a declassification and
/// carries the host's label for the data it releases (#3258), which is the
/// label the released effect's signed record names.
///
/// A-19: listing every approval as `Ordinary` (dropping the hold from the
/// view) reds this.
fn declassifying(review: nucleus_spec::host_effect_approval::ApprovalReview) -> uuid::Uuid {
    let crate::host_decide::effects::ApprovalCategory::Declassification { input } =
        review.approval.category
    else {
        panic!(
            "a held push was shown as {:?}, not a declassification",
            review.approval.category
        );
    };
    assert_eq!(
        input.integrity,
        nucleus_decision_protocol::IntegLevel::Adversarial
    );
    review.approval.id
}

/// **The acceptance journey.** In one pod, after a model call: the push's
/// advertisement and its pack are each held for approval and refused without
/// it; approved, each proceeds; a reused approval is refused; and each
/// released half's signed record names its approval and the tainted labels it
/// declassified, while the model call's record carries none.
///
/// A-19: deciding the push with the abort-only `decide_term_with_flow` again
/// (no hold) reds the first assertion — the host refuses it as
/// `flow_refused`; leaving the approval `Granted` at commit reds the reuse
/// assertion.
#[tokio::test]
async fn after_a_model_call_a_push_is_held_approved_once_and_declassified() {
    let (pod, hits) = one_pod(PermissionLattice::permissive()).await;
    model_call(&pod).await;

    // Held, not refused, and without an approval nothing leaves.
    let held = drive(&pod, &advertise("git-receive-pack", "adv"), b"").await;
    assert!(
        held.head.reason.starts_with("host approval required:"),
        "a tainted push must be held for approval, not refused: {:?}",
        held.head
    );
    assert!(hits.lock().unwrap().is_empty(), "an unapproved push left");
    let advert = declassifying(grant_pending(&pod));
    let adv = drive(&pod, &advertise("git-receive-pack", "adv-approved"), b"").await;
    assert!(adv.head.granted, "{:?}", adv.head);

    let unapproved = drive(&pod, &receive_pack("pack"), b"0000PACK").await;
    assert!(!unapproved.head.granted);
    assert!(
        unapproved
            .head
            .reason
            .starts_with("host approval required:")
    );
    assert_eq!(hits.lock().unwrap().len(), 1, "only the advertisement left");
    let pack = declassifying(grant_pending(&pod));
    let pushed = drive(&pod, &receive_pack("pack-approved"), b"0000PACK").await;
    assert!(pushed.head.granted, "{:?}", pushed.head);
    assert_eq!(pushed.body, RESULT);

    // The same request again: its approval is spent, so it is held afresh.
    let reused = drive(&pod, &receive_pack("pack-reused"), b"0000PACK").await;
    assert!(
        !reused.head.granted,
        "a spent approval released a second push"
    );
    assert!(reused.head.reason.starts_with("host approval required:"));
    let sent: Vec<_> = hits
        .lock()
        .unwrap()
        .iter()
        .map(|h| h.method.clone())
        .collect();
    assert_eq!(
        sent,
        ["GET", "POST"],
        "exactly the two approved requests left"
    );

    // The receipts: flow evidence, never the payload.
    let records = records(&pod);
    assert_eq!(records.len(), 3, "model call, advertisement, pack");
    assert_eq!(records[0].authorization.operation, "web_fetch");
    assert!(records[0].authorization.declassification.is_none());
    for (record, approval) in records[1..].iter().zip([advert, pack]) {
        let claim = &record.authorization;
        assert_eq!(claim.operation, "git_push");
        let declassified = claim
            .declassification
            .as_ref()
            .expect("a released tainted push names its declassification");
        assert_eq!(declassified.approval_id, approval);
        assert_eq!(
            declassified.input.integrity,
            nucleus_decision_protocol::IntegLevel::Adversarial
        );
    }
    let log = std::fs::read_to_string(pod.dir.path().join(host_effect::LOG_FILE)).unwrap();
    assert!(!log.contains("PACK"), "the record copied the payload");
}

/// Without a taint there is nothing to declassify: the same profile's push
/// from a fresh pod is approved as before and its record carries none.
#[tokio::test]
async fn an_untainted_push_records_no_declassification() {
    let (pod, _hits) = one_pod(PermissionLattice::permissive()).await;
    let asked = drive(&pod, &receive_pack("clean"), b"0000PACK").await;
    assert!(asked.head.reason.starts_with("host approval required:"));
    let review = grant_pending(&pod);
    assert_eq!(
        review.approval.category,
        crate::host_decide::effects::ApprovalCategory::Ordinary,
        "an untainted push is not a declassification"
    );
    let pushed = drive(&pod, &receive_pack("clean-approved"), b"0000PACK").await;
    assert!(pushed.head.granted, "{:?}", pushed.head);
    let records = records(&pod);
    assert_eq!(records.len(), 1);
    assert!(records[0].authorization.declassification.is_none());
}

/// Under `git_push: never` there is no exit: after the model call, both
/// halves of the push are refused, nothing is held for an operator, and
/// nothing leaves.
#[tokio::test]
async fn under_never_a_push_after_a_model_call_is_refused_before_leaving() {
    let mut never = PermissionLattice::permissive();
    never.capabilities.git_push = portcullis::CapabilityLevel::Never;
    let (pod, hits) = one_pod(never).await;
    model_call(&pod).await;
    for heard in [
        drive(&pod, &advertise("git-receive-pack", "never-adv"), b"").await,
        drive(&pod, &receive_pack("never-pack"), b"0000PACK").await,
    ] {
        assert!(!heard.head.granted, "{:?}", heard.head);
        assert!(!heard.head.reason.starts_with("host approval required:"));
    }
    assert!(hits.lock().unwrap().is_empty());
    let pending = pod
        .host_policy
        .lock()
        .unwrap()
        .list_effect_approvals(operator(), now());
    assert!(pending.is_empty(), "{pending:?}");
}
