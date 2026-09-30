//! gRPC pod handlers scope the caller exactly as HTTP does: by
//! `AuthorizationPolicy::caller_scope`, from the caller token AND the verified
//! peer. Run against the real `GrpcService` over a real `NodeState` (the
//! `handler_tests` fixture), with the interceptor's `AuthContext` placed in
//! the request extensions the way `serve_grpc` places it.

use super::handler_tests::{register, register_labelled, state};
use super::*;
use crate::proto;
use crate::proto::node_service_server::NodeService;

fn pod_svid(pod: Uuid) -> String {
    format!("spiffe://nucleus.local/ns/pods/sa/{pod}")
}

/// A request as the interceptor hands it on: the peer's verified identity in
/// the extensions, optionally a caller token in the metadata.
fn req<T>(msg: T, peer: Option<&str>, token_for: Option<(Uuid, &NodeState)>) -> tonic::Request<T> {
    let mut r = tonic::Request::new(msg);
    if let Some(spiffe) = peer {
        r.extensions_mut()
            .insert(crate::auth::AuthContext::from_spiffe(spiffe.to_string()));
    }
    if let Some((pod, st)) = token_for {
        let token = crate::pod_caller_identity::derive_token(st.caller_secret.as_ref(), pod);
        let md = r.metadata_mut();
        md.insert(
            nucleus_client::HEADER_POD_ID,
            pod.to_string().parse().unwrap(),
        );
        md.insert(nucleus_client::HEADER_POD_TOKEN, token.parse().unwrap());
    }
    r
}

fn code<T>(r: Result<T, tonic::Status>) -> Option<tonic::Code> {
    r.err().map(|s| s.code())
}

fn svc(st: &NodeState) -> crate::GrpcService {
    crate::GrpcService { state: st.clone() }
}

async fn listed(st: &NodeState, peer: &str, token: Option<Uuid>) -> Vec<String> {
    let resp = svc(st)
        .list_pods(req(proto::Empty {}, Some(peer), token.map(|p| (p, st))))
        .await
        .expect("an authorized peer lists");
    resp.into_inner().pods.into_iter().map(|p| p.id).collect()
}

async fn running(st: &NodeState, id: Uuid) -> bool {
    matches!(
        get_pod(st, id)
            .await
            .expect("registered")
            .info()
            .await
            .state,
        crate::PodState::Running
    )
}

async fn cancel_all(st: &NodeState) {
    let pods: Vec<_> = st.pods.lock().await.values().cloned().collect();
    for p in pods {
        let _ = p.cancel().await;
    }
}

/// A pod peer that sends no caller token is still its own pod: it lists only
/// itself and its child, and every by-id operation on a sibling is NOT_FOUND —
/// get, logs, stream, watch, receipt and cancel — with the sibling untouched.
#[tokio::test]
async fn a_pod_peer_without_a_token_is_scoped_to_its_own_lineage() {
    let dir = tempfile::tempdir().expect("tempdir");
    let st = state(&dir);
    let a = register(&st, None).await;
    let b = register(&st, None).await;
    let child_of_a = register(&st, Some(a)).await;
    let peer = pod_svid(a);
    let p = Some(peer.as_str());

    let mut seen = listed(&st, &peer, None).await;
    seen.sort();
    let mut want = vec![a.to_string(), child_of_a.to_string()];
    want.sort();
    assert_eq!(
        seen, want,
        "a tokenless pod peer lists only its own lineage"
    );

    let sib = b.to_string();
    let nf = Some(tonic::Code::NotFound);
    let s = svc(&st);
    let get = s.get_pod(req(
        proto::GetPodRequest {
            pod_id: sib.clone(),
        },
        p,
        None,
    ));
    assert_eq!(code(get.await), nf, "get");
    let logs = s.pod_logs(req(proto::PodId { id: sib.clone() }, p, None));
    assert_eq!(code(logs.await), nf, "logs");
    let stream = proto::StreamLogsRequest {
        pod_id: sib.clone(),
        ..Default::default()
    };
    assert_eq!(
        code(s.stream_pod_logs(req(stream, p, None)).await),
        nf,
        "stream"
    );
    let watch = proto::WatchPodRequest {
        pod_id: sib.clone(),
        ..Default::default()
    };
    assert_eq!(
        code(s.watch_pod_state(req(watch, p, None)).await),
        nf,
        "watch"
    );
    let receipt = proto::GetReceiptRequest {
        pod_id: sib.clone(),
    };
    assert_eq!(
        code(s.get_receipt(req(receipt, p, None)).await),
        nf,
        "receipt"
    );
    let cancel = s.cancel_pod(req(proto::PodId { id: sib.clone() }, p, None));
    assert_eq!(code(cancel.await), nf, "cancel");
    assert!(
        running(&st, b).await,
        "a refused cancel leaves the sibling running"
    );
    cancel_all(&st).await;
}

/// A valid caller still works: the pod peer reaches itself and cancels its own
/// child, with or without its token; a token names the same pod its SVID does.
#[tokio::test]
async fn a_pod_peer_still_manages_its_own_lineage() {
    let dir = tempfile::tempdir().expect("tempdir");
    let st = state(&dir);
    let a = register(&st, None).await;
    let child = register(&st, Some(a)).await;
    let peer = pod_svid(a);
    let s = svc(&st);

    let own = req(
        proto::GetPodRequest {
            pod_id: a.to_string(),
        },
        Some(&peer),
        None,
    );
    assert!(s.get_pod(own).await.is_ok(), "a pod reaches itself");
    assert_eq!(
        listed(&st, &peer, Some(a)).await.len(),
        2,
        "with its token too"
    );
    let cancel = req(
        proto::PodId {
            id: child.to_string(),
        },
        Some(&peer),
        Some((a, &st)),
    );
    assert!(
        s.cancel_pod(cancel).await.is_ok(),
        "a pod cancels its child"
    );
    assert!(!running(&st, child).await, "and the child stops");
    cancel_all(&st).await;
}

/// The node-wide identities the policy names are unscoped, as before.
#[tokio::test]
async fn an_orchestrator_peer_sees_every_pod() {
    let dir = tempfile::tempdir().expect("tempdir");
    let st = state(&dir);
    for _ in 0..3 {
        register(&st, None).await;
    }
    let orch = "spiffe://nucleus.local/ns/default/sa/orchestrator";
    assert_eq!(listed(&st, orch, None).await.len(), 3);
    cancel_all(&st).await;
}

/// No verified peer is refused, never unscoped; and an identity the policy
/// admits under the pod prefix but which names no pod is refused, not widened.
#[tokio::test]
async fn a_caller_the_policy_cannot_place_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let st = state(&dir);
    register(&st, None).await;

    let bare = req(proto::Empty {}, None, None);
    let got = grpc_caller(&st, bare.metadata(), bare.extensions());
    assert_eq!(
        got.err().map(|s| s.code()),
        Some(tonic::Code::Unauthenticated)
    );
    assert!(
        svc(&st)
            .list_pods(req(proto::Empty {}, None, None))
            .await
            .is_err()
    );

    let nameless = Some("spiffe://nucleus.local/ns/pods/sa/not-a-pod");
    let r = svc(&st)
        .list_pods(req(proto::Empty {}, nameless, None))
        .await;
    assert_eq!(
        r.err().map(|s| s.code()),
        Some(tonic::Code::PermissionDenied)
    );
    cancel_all(&st).await;
}

/// HTTP resolves through the same function: a pod SVID with no token is that
/// pod, not the unscoped answer.
#[tokio::test]
async fn http_resolves_a_tokenless_pod_peer_to_its_own_pod() {
    let dir = tempfile::tempdir().expect("tempdir");
    let st = state(&dir);
    let a = Uuid::new_v4();
    let ctx = crate::auth::AuthContext::from_spiffe(pod_svid(a));
    let headers = axum::http::HeaderMap::new();
    let got = crate::auth::resolve_http_caller(&st, &ctx, &headers).expect("a pod resolves");
    assert_eq!(got, crate::auth::CallerScope::Pod(a));
}

/// A CI/CD peer is scoped to the pods it created — those the node stamped with
/// its identity — and nothing else: it lists them alone, and every by-id
/// operation on any other pod is NOT_FOUND, with that pod untouched. It used to
/// resolve to the operator's unscoped view.
#[tokio::test]
async fn a_ci_peer_manages_only_the_pods_stamped_with_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let st = state(&dir);
    let ci = "spiffe://nucleus.local/ns/github/sa/org-repo";
    let label = crate::auth::CI_PRINCIPAL_LABEL;
    let mine = register_labelled(&st, None, &[(label, ci)]).await;
    let theirs = register_labelled(
        &st,
        None,
        &[(label, "spiffe://nucleus.local/ns/github/sa/org-other")],
    )
    .await;
    let unstamped = register(&st, None).await;

    assert_eq!(
        listed(&st, ci, None).await,
        vec![mine.to_string()],
        "a CI peer lists only its own pods"
    );
    let s = svc(&st);
    for other in [theirs, unstamped] {
        let get = s.get_pod(req(
            proto::GetPodRequest {
                pod_id: other.to_string(),
            },
            Some(ci),
            None,
        ));
        assert_eq!(code(get.await), Some(tonic::Code::NotFound), "get {other}");
        let cancel = s.cancel_pod(req(
            proto::PodId {
                id: other.to_string(),
            },
            Some(ci),
            None,
        ));
        assert_eq!(
            code(cancel.await),
            Some(tonic::Code::NotFound),
            "cancel {other}"
        );
        assert!(running(&st, other).await, "{other} is untouched");
    }
    let own = s.cancel_pod(req(
        proto::PodId {
            id: mine.to_string(),
        },
        Some(ci),
        None,
    ));
    assert!(own.await.is_ok(), "a CI peer cancels its own pod");
    cancel_all(&st).await;
}

/// The stamp is the node's: a create whose spec sets it is refused as an
/// invalid spec before anything is admitted, whoever sends it. Drives the real
/// HTTP handler, so it holds the line in `create_pod_internal` that stamps.
#[tokio::test]
async fn a_create_that_sets_the_ci_principal_label_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let st = state(&dir);
    let body = format!(
        r#"{{"apiVersion":"nucleus/v1","kind":"Pod","metadata":{{"labels":{{"{}":"spiffe://nucleus.local/ns/github/sa/org-other"}}}},"spec":{{}}}}"#,
        crate::auth::CI_PRINCIPAL_LABEL
    );
    let ci = "spiffe://nucleus.local/ns/github/sa/org-repo";
    let r = crate::create_pod(
        axum::extract::State(st.clone()),
        axum::Extension(crate::auth::CallerScope::CiPrincipal(ci.to_string())),
        axum::Extension(crate::auth::AuthContext::from_spiffe(ci.to_string())),
        axum::http::HeaderMap::new(),
        axum::body::Bytes::from(body),
    )
    .await;
    match r {
        Err(crate::ApiError::InvalidSpec(msg)) => assert!(
            msg.contains(crate::auth::CI_PRINCIPAL_LABEL),
            "the refusal names the label: {msg}"
        ),
        Err(e) => panic!("refused for the wrong reason: {e}"),
        Ok(_) => panic!("a spec that sets the node's stamp was admitted"),
    }
    assert!(st.pods.lock().await.is_empty(), "and nothing was created");
}
