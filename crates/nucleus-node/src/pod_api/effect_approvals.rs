//! Operator-only approvals stored on the host, never in the guest.
use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use uuid::Uuid;

use crate::auth::AuthContext;
use crate::host_decide::effects::{ApprovalView, Operator};
use crate::{ApiError, NodeState};

pub(crate) fn routes() -> Router<NodeState> {
    Router::new()
        .route("/v1/pods/{id}/effect-approvals", get(list))
        .route("/v1/pods/{id}/effect-approvals/{approval}", post(settle))
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum Decision {
    Grant,
    Refuse,
}

fn operator(auth: &AuthContext, state: &NodeState) -> Result<Operator, ApiError> {
    Operator::authenticate(&auth.spiffe_id, state.authority.root_minter())
        .map_err(|e| ApiError::Authority(e.into()))
}

fn now() -> Result<u64, ApiError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|e| ApiError::Driver(e.to_string()))
}

fn policy_error(e: crate::pod_authority::HostKernelError) -> ApiError {
    use crate::pod_authority::HostKernelError;
    match e {
        HostKernelError::NoCertificate => ApiError::NotFound,
        HostKernelError::HistoryUnavailable | HostKernelError::EvidenceUnavailable(_) => {
            ApiError::SupervisorUnavailable(e.to_string())
        }
        HostKernelError::DoesNotVerify(reason) => ApiError::Authority(reason),
    }
}

async fn list(
    State(state): State<NodeState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<ApprovalView>>, ApiError> {
    let operator = operator(&auth, &state)?;
    let policy = state
        .authority
        .host_policy(id)
        .await
        .map_err(policy_error)?;
    let mut policy = policy
        .lock()
        .map_err(|_| ApiError::SupervisorUnavailable("host policy fault".into()))?;
    Ok(Json(policy.list_effect_approvals(operator, now()?)))
}

async fn settle(
    State(state): State<NodeState>,
    Extension(auth): Extension<AuthContext>,
    Path((id, approval)): Path<(Uuid, Uuid)>,
    Json(decision): Json<Decision>,
) -> Result<StatusCode, ApiError> {
    let operator = operator(&auth, &state)?;
    let policy = state
        .authority
        .host_policy(id)
        .await
        .map_err(policy_error)?;
    let mut policy = policy
        .lock()
        .map_err(|_| ApiError::SupervisorUnavailable("host policy fault".into()))?;
    policy
        .settle_effect_approval(
            operator,
            approval,
            matches!(decision, Decision::Grant),
            now()?,
        )
        .map_err(|e| ApiError::Body(e.into()))?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request};
    use nucleus_decision_protocol::ArgsDigest;
    use tower::ServiceExt;

    #[tokio::test]
    async fn operator_routes_grant_real_admitted_pod_effects_and_refuse_guests() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::pod_api::handler_tests::state(&dir);
        let root = state.authority.root_minter().to_string();
        state.authz_policy = state.authz_policy.with_operator_identity(&root);
        let id = Uuid::new_v4();
        let mut lattice = portcullis::PermissionLattice::permissive();
        lattice.obligations.insert(portcullis::Operation::GitCommit);
        let mut spec: nucleus_spec::PodSpec = serde_json::from_value(serde_json::json!({
            "apiVersion": "nucleus/v1", "kind": "Pod", "metadata": {"name": "approvals"},
            "spec": {"work_dir": "/work"}
        }))
        .unwrap();
        spec.spec.policy = nucleus_spec::PolicySpec::Inline {
            lattice: Box::new(lattice),
        };
        state
            .authority
            .admit_kept(
                &crate::pod_authority::Admission {
                    caller_spiffe_id: root.clone(),
                    caller_pod: None,
                    header_cert: None,
                },
                &spec,
                id,
            )
            .await
            .unwrap();
        let policy = state.authority.host_policy(id).await.unwrap();
        let digest = ArgsDigest::new([3; 32]);
        assert!(
            policy
                .lock()
                .unwrap()
                .preflight_effect(
                    digest,
                    portcullis::Operation::GitCommit,
                    "https://upstream.invalid/commit",
                    now().unwrap()
                )
                .is_err()
        );
        let path = format!("/v1/pods/{id}/effect-approvals");
        assert_eq!(
            crate::auth::operation_for_route(&Method::GET, &path),
            Some(crate::auth::Operation::ApproveEffect)
        );
        let app = routes().with_state(state.clone());
        let request = |method: Method, path: &str, identity: &str, body: &str| {
            Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json")
                .extension(AuthContext::from_spiffe(identity.into()))
                .body(Body::from(body.to_string()))
                .unwrap()
        };
        let guest = format!("spiffe://nucleus.local/ns/pods/sa/{id}");
        assert!(
            state
                .authz_policy
                .authorize(
                    &AuthContext::from_spiffe(guest.clone()),
                    crate::auth::Operation::ApproveEffect
                )
                .is_err()
        );
        let denied = app
            .clone()
            .oneshot(request(Method::GET, &path, &guest, ""))
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        let response = app
            .clone()
            .oneshot(request(Method::GET, &path, &root, ""))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let views: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let settle_path = format!("{path}/{}", views[0]["id"].as_str().unwrap());
        assert_eq!(
            crate::auth::operation_for_route(&Method::POST, &settle_path),
            Some(crate::auth::Operation::ApproveEffect)
        );
        for (identity, expected) in [
            (&guest, StatusCode::FORBIDDEN),
            (&root, StatusCode::NO_CONTENT),
            (&root, StatusCode::BAD_REQUEST),
        ] {
            let response = app
                .clone()
                .oneshot(request(Method::POST, &settle_path, identity, "\"grant\""))
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }
        let _permit = policy
            .lock()
            .unwrap()
            .authorize_effect(
                digest,
                portcullis::Operation::GitCommit,
                "https://upstream.invalid/commit",
                now().unwrap(),
            )
            .unwrap();
        let journal = state
            .state_dir
            .join("pods")
            .join(id.to_string())
            .join(nucleus_spec::host_effect::LOG_FILE);
        let record: nucleus_spec::host_effect::SignedAuthorization =
            serde_json::from_str(std::fs::read_to_string(journal).unwrap().trim()).unwrap();
        assert_eq!(record.authorization.pod_id, id.to_string());
        let public: [u8; 32] = hex::decode(state.authority.root_pubkey_hex())
            .unwrap()
            .try_into()
            .unwrap();
        let key = ed25519_dalek::VerifyingKey::from_bytes(&public).unwrap();
        let signature =
            ed25519_dalek::Signature::from_slice(&hex::decode(record.signature).unwrap()).unwrap();
        key.verify_strict(
            &nucleus_spec::host_effect::signing_bytes(&record.authorization).unwrap(),
            &signature,
        )
        .unwrap();
    }
}
