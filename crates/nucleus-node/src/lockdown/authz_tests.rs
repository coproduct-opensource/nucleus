//! `NodeService::Lockdown` is authorized as `auth::Operation::Lockdown`: the
//! operator and the orchestrators may issue or lift one; a pod may not, whatever
//! it names. Run against the real `GrpcService` over the real `NodeState` (the
//! pod-API `handler_tests` fixture), with the interceptor's `AuthContext` in the
//! request extensions the way `serve_grpc` places it.

use crate::pod_api::handler_tests::{register, state};
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
