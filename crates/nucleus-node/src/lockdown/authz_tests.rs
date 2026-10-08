//! `NodeService::Lockdown` is authorized as `auth::Operation::Lockdown`: the
//! operator and the orchestrators may issue or lift one; a pod may not, whatever
//! it names. Run against the real `GrpcService` over the real `NodeState` (the
//! pod-API `handler_tests` fixture), with the interceptor's `AuthContext` in the
//! request extensions the way `serve_grpc` places it.

use crate::pod_api::handler_tests::{register, register_labelled, state};
use crate::proto;
use crate::proto::lockdown_request::Scope;
use crate::proto::node_service_server::NodeService;
use tokio::sync::broadcast::error::TryRecvError;
use uuid::Uuid;

const OPERATOR: &str = "spiffe://nucleus.local/ns/system/sa/cli";
const ORCHESTRATOR: &str = "spiffe://nucleus.local/ns/default/sa/orchestrator";

fn pod_svid(pod: Uuid) -> String {
    format!("spiffe://nucleus.local/ns/pods/sa/{pod}")
}

fn request(
    peer: &str,
    scope: Option<Scope>,
    restore: bool,
) -> tonic::Request<proto::LockdownRequest> {
    let mut r = tonic::Request::new(proto::LockdownRequest {
        scope,
        reason: "test".to_string(),
        operator_id: "test".to_string(),
        restore,
    });
    r.extensions_mut()
        .insert(crate::auth::AuthContext::from_spiffe(peer.to_string()));
    r
}

fn node(dir: &tempfile::TempDir) -> crate::NodeState {
    let mut st = state(dir);
    st.authz_policy = st.authz_policy.clone().with_operator_identity(OPERATOR);
    st
}

async fn cancel_all(st: &crate::NodeState) {
    let pods: Vec<_> = st.pods.lock().await.values().cloned().collect();
    for p in pods {
        let _ = p.cancel().await;
    }
}

/// Every scope a request can name, in both directions.
fn every_request_shape(own: Uuid, other: Uuid) -> Vec<(Option<Scope>, bool)> {
    let scopes = [
        None,
        Some(Scope::PodId(other.to_string())),
        Some(Scope::PodId(own.to_string())),
        Some(Scope::LabelSelector(String::new())),
    ];
    scopes
        .into_iter()
        .flat_map(|s| [(s.clone(), false), (s, true)])
        .collect()
}

/// A pod may neither issue nor lift a lockdown — node-wide, on another pod, or
/// on itself — and a refused request broadcasts nothing to any watcher.
#[tokio::test]
async fn a_pod_cannot_issue_or_lift_a_lockdown() {
    let dir = tempfile::tempdir().expect("tempdir");
    let st = node(&dir);
    let a = register(&st, None).await;
    let b = register(&st, None).await;
    let child_of_a = register(&st, Some(a)).await;
    let mut heard = st.lockdown_tx.subscribe();
    let svc = crate::GrpcService { state: st.clone() };

    for caller in [a, child_of_a] {
        for (scope, restore) in every_request_shape(caller, b) {
            let shape = format!("caller={caller} scope={scope:?} restore={restore}");
            let got = svc
                .lockdown(request(&pod_svid(caller), scope, restore))
                .await;
            assert_eq!(
                got.err().map(|s| s.code()),
                Some(tonic::Code::PermissionDenied),
                "{shape}"
            );
            assert_eq!(heard.try_recv().err(), Some(TryRecvError::Empty), "{shape}");
        }
    }
    cancel_all(&st).await;
}

/// The operator and the orchestrators issue and lift lockdowns, and each one is
/// broadcast with the direction it was asked for.
#[tokio::test]
async fn the_operator_issues_and_lifts_a_lockdown() {
    let dir = tempfile::tempdir().expect("tempdir");
    let st = node(&dir);
    let a = register(&st, None).await;
    let mut heard = st.lockdown_tx.subscribe();
    let svc = crate::GrpcService { state: st.clone() };

    for peer in [OPERATOR, ORCHESTRATOR] {
        for (scope, restore) in [
            (None, false),
            (None, true),
            (Some(Scope::PodId(a.to_string())), false),
            (Some(Scope::PodId(a.to_string())), true),
        ] {
            let shape = format!("peer={peer} scope={scope:?} restore={restore}");
            let resp = svc
                .lockdown(request(peer, scope, restore))
                .await
                .unwrap_or_else(|e| panic!("{shape}: {e}"));
            assert_eq!(resp.into_inner().affected_pods, 1, "{shape}");
            let cmd = heard.try_recv().unwrap_or_else(|e| panic!("{shape}: {e}"));
            assert_eq!(cmd.active, !restore, "{shape}");
        }
    }
    cancel_all(&st).await;
}

/// **The label leak, on the real registry.** The operator issues a label
/// lockdown that matches pod A's labels and not pod B's. B's watcher is sent
/// nothing: not the reason, and not the selector naming A's labels. A is sent
/// the command, and the audit counts only A, the same set the node delivers to.
#[tokio::test]
async fn a_label_lockdown_is_delivered_only_to_the_pods_it_matches() {
    let dir = tempfile::tempdir().expect("tempdir");
    let st = node(&dir);
    let a = register_labelled(&st, None, &[("tier", "prod")]).await;
    let b = register_labelled(&st, None, &[("tier", "dev")]).await;
    let mut heard = st.lockdown_tx.subscribe();
    let svc = crate::GrpcService { state: st.clone() };
    let selector = || Some(Scope::LabelSelector("tier=prod".to_string()));

    let mut issue = request(OPERATOR, selector(), false);
    issue.get_mut().reason = "pod-a-specific reason".to_string();
    let resp = svc.lockdown(issue).await.expect("operator may lock down");
    assert_eq!(resp.into_inner().affected_pods, 1);
    let cmd = heard.try_recv().expect("the node broadcasts internally");

    let to_b = crate::lockdown::delivery(&st, &cmd, b).await;
    assert!(
        to_b.is_none(),
        "pod B, which the selector does not match, was sent {to_b:?}"
    );
    let to_a = crate::lockdown::delivery(&st, &cmd, a)
        .await
        .expect("pod A, which the selector matches, must be sent the lockdown");
    assert!(to_a.active);
    assert_eq!(to_a.scope, "label:tier=prod");
    assert_eq!(to_a.reason, "pod-a-specific reason");

    // The lift follows the same rule.
    svc.lockdown(request(OPERATOR, selector(), true))
        .await
        .expect("operator may lift");
    let lift = heard.try_recv().expect("lift broadcast");
    assert!(
        crate::lockdown::delivery(&st, &lift, b)
            .await
            .is_none()
    );
    assert!(
        crate::lockdown::delivery(&st, &lift, a)
            .await
            .is_some()
    );
    cancel_all(&st).await;
}

fn labelled(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

/// **A label lockdown is held.** A pod the selector matches that is registered,
/// and whose watcher connects, after the lockdown went out is told it. A pod it
/// does not match is told nothing, and once the selector is lifted neither is.
#[tokio::test]
async fn a_matching_pod_that_connects_after_a_label_lockdown_is_told() {
    let dir = tempfile::tempdir().expect("tempdir");
    let st = node(&dir);
    let svc = crate::GrpcService { state: st.clone() };
    let selector = || Some(Scope::LabelSelector("tier=prod".to_string()));
    svc.lockdown(request(OPERATOR, selector(), false))
        .await
        .expect("operator may lock down");

    let late = register_labelled(&st, None, &[("tier", "prod")]).await;
    let other = register_labelled(&st, None, &[("tier", "dev")]).await;
    let told = crate::lockdown::in_force(&st, late)
        .await
        .expect("a matching pod that connects later must be told the lockdown in force");
    assert!(told.active);
    assert_eq!(told.scope, "label:tier=prod");
    assert_eq!(crate::lockdown::in_force(&st, other).await, None);

    svc.lockdown(request(OPERATOR, selector(), true))
        .await
        .expect("operator may lift");
    assert_eq!(crate::lockdown::in_force(&st, late).await, None);
    cancel_all(&st).await;
}

/// **A label lockdown refuses creating a pod it matches, until it is lifted.**
/// The create is refused through the real create path, whoever asks -- here
/// the operator's own root identity -- and the refusal names the lockdown by
/// its selector and issue time, never its reason. A pod already under it may
/// not create either. Lifting the selector admits both again.
#[tokio::test]
async fn a_label_lockdown_refuses_creating_a_pod_it_matches_until_lifted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let st = node(&dir);
    let svc = crate::GrpcService { state: st.clone() };
    let selector = || Some(Scope::LabelSelector("tier=prod".to_string()));
    let mut issue = request(OPERATOR, selector(), false);
    issue.get_mut().reason = "do-not-disclose".to_string();
    let issued = svc
        .lockdown(issue)
        .await
        .expect("operator may lock down")
        .into_inner()
        .timestamp_unix;

    let spec = |pairs: &[(&str, &str)]| {
        let work = st.state_dir.join("w");
        std::fs::create_dir_all(&work).expect("work dir");
        let mut spec: nucleus_spec::PodSpec =
            serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{}}"#)
                .expect("minimal spec");
        spec.spec.work_dir = work;
        spec.metadata.labels = labelled(pairs);
        spec
    };
    let root = crate::pod_authority::Admission {
        caller_spiffe_id: st.authority.root_minter().to_string(),
        caller_pod: None,
        header_cert: None,
    };
    let got = crate::create_pod_internal(&st, spec(&[("tier", "prod")]), None, None, root).await;
    match got {
        Err(crate::ApiError::Authority(why)) => {
            assert!(why.contains("label:tier=prod"), "{why}");
            assert!(why.contains(&issued.to_string()), "{why}");
            assert!(!why.contains("do-not-disclose"), "the reason leaked: {why}");
        }
        other => panic!("a create the label lockdown matches was not refused: {other:?}"),
    }
    let prod = labelled(&[("tier", "prod")]);
    let dev = labelled(&[("tier", "dev")]);
    let none = labelled(&[]);
    assert!(crate::lockdown::admits(&st, None, &dev).await.is_ok());
    let under = register_labelled(&st, None, &[("tier", "prod")]).await;
    assert!(
        crate::lockdown::admits(&st, Some(under), &none)
            .await
            .is_err(),
        "a pod the label lockdown covers created a child"
    );

    svc.lockdown(request(OPERATOR, selector(), true))
        .await
        .expect("operator may lift");
    assert!(crate::lockdown::admits(&st, None, &prod).await.is_ok());
    assert!(
        crate::lockdown::admits(&st, Some(under), &none)
            .await
            .is_ok()
    );
    cancel_all(&st).await;
}

/// **A scope the node cannot parse is refused at issue.** It used to be held
/// nowhere and delivered to every watcher, reason and all. Now nothing is
/// broadcast and nothing is held.
#[tokio::test]
async fn an_unparseable_scope_is_refused_and_broadcast_to_nobody() {
    let dir = tempfile::tempdir().expect("tempdir");
    let st = node(&dir);
    let a = register(&st, None).await;
    let mut heard = st.lockdown_tx.subscribe();
    let svc = crate::GrpcService { state: st.clone() };
    for scope in [
        Scope::PodId("not-a-uuid".to_string()),
        Scope::LabelSelector("tier".to_string()),
    ] {
        let got = svc
            .lockdown(request(OPERATOR, Some(scope.clone()), false))
            .await;
        assert_eq!(
            got.err().map(|s| s.code()),
            Some(tonic::Code::InvalidArgument),
            "{scope:?}"
        );
        assert_eq!(heard.try_recv().err(), Some(TryRecvError::Empty), "{scope:?}");
        assert_eq!(crate::lockdown::in_force(&st, a).await, None, "{scope:?}");
    }
    cancel_all(&st).await;
}

/// **Only a pod watches.** A peer that is not a pod -- the operator itself --
/// is refused the stream, rather than sent every command unfiltered. A pod
/// peer resolves to its own pod.
#[test]
fn only_a_pod_may_watch_for_lockdowns() {
    let dir = tempfile::tempdir().expect("tempdir");
    let st = node(&dir);
    let resolve = |peer: &str| {
        let mut ext = tonic::Extensions::new();
        ext.insert(crate::auth::AuthContext::from_spiffe(peer.to_string()));
        crate::lockdown::watcher(&st, &tonic::metadata::MetadataMap::new(), &ext)
    };
    for peer in [OPERATOR, ORCHESTRATOR] {
        assert_eq!(
            resolve(peer).map_err(|s| s.code()),
            Err(tonic::Code::PermissionDenied),
            "{peer}"
        );
    }
    let pod = Uuid::new_v4();
    assert_eq!(resolve(&pod_svid(pod)).map_err(|s| s.code()), Ok(pod));
}
