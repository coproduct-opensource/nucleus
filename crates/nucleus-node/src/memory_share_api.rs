//! The issuing path for `SharedMemory` grants: mint, narrow, revoke, list (`memory_share`).
//!
//! # Who may call it
//!
//! A tenant's root identity, and only for its own tenant: the tenant a request acts for is the
//! hash of the caller's verified SPIFFE ID, the same root identity a pod it creates is issued
//! under (`AdmittedPodPlan::owner`). Nothing in the request body names a tenant, so no caller can
//! mint for another. A pod is never a tenant root, and neither is a CI/CD identity: both are
//! refused before the registry is read (`Operation::MemoryShare` refuses them at the route too).
use axum::extract::{Extension, Path, State};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{AuthContext, CallerScope};
use crate::memory_share::{self, FlowClaim, Narrowing, TenantKey};
use crate::{ApiError, NodeState};

pub(crate) fn routes() -> Router<NodeState> {
    Router::new()
        .route("/v1/memory/grants", post(mint).get(list))
        .route("/v1/memory/grants/{id}/attenuate", post(attenuate))
        .route("/v1/memory/shares/{share}/revoke", post(revoke))
}

/// The tenant a caller is the root of, or a refusal for a caller that is no tenant's root.
fn tenant_root(caller: &CallerScope, auth: &AuthContext) -> Result<TenantKey, ApiError> {
    match caller {
        CallerScope::NodeWide | CallerScope::Tenant(_) => Ok(TenantKey::of(&auth.spiffe_id)),
        CallerScope::Pod(_) | CallerScope::CiPrincipal(_) => Err(ApiError::Authority(
            "only a tenant's root identity mints, narrows or revokes SharedMemory grants".into(),
        )),
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn registry(state: &NodeState) -> Result<&std::sync::Mutex<memory_share::Registry>, ApiError> {
    state.memory.shares().ok_or_else(|| {
        ApiError::InvalidSpec("SharedMemory grants require an operator --memory-root".into())
    })
}

/// A request to mint: the share, the namespace it serves, who may read and write, and until when.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MintRequest {
    share: String,
    namespace: String,
    readers: std::collections::BTreeSet<memory_share::Holder>,
    writers: std::collections::BTreeSet<memory_share::Holder>,
    expiry: memory_share::Expiry,
}

#[derive(Debug, Serialize)]
pub(crate) struct Minted {
    grant: Uuid,
}

#[derive(Debug, Serialize)]
pub(crate) struct Revoked {
    share: String,
    epoch: u64,
}

async fn mint(
    State(state): State<NodeState>,
    Extension(caller): Extension<CallerScope>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<MintRequest>,
) -> Result<Json<Minted>, ApiError> {
    let tenant = tenant_root(&caller, &auth)?;
    let MintRequest {
        share,
        namespace,
        readers,
        writers,
        expiry,
    } = request;
    let holders = Narrowing {
        readers,
        writers,
        expiry,
    };
    let grant = registry(&state)?
        .lock()
        .map_err(|_| ApiError::Driver("memory share registry unavailable".into()))?
        .mint(
            &tenant,
            &share,
            &namespace,
            holders,
            now(),
            &mut |claim: &FlowClaim<'_>| {
                memory_share::record(&state.state_dir, &state.authority, claim)
            },
        )?;
    Ok(Json(Minted { grant }))
}

async fn attenuate(
    State(state): State<NodeState>,
    Extension(caller): Extension<CallerScope>,
    Extension(auth): Extension<AuthContext>,
    Path(parent): Path<Uuid>,
    Json(narrower): Json<Narrowing>,
) -> Result<Json<Minted>, ApiError> {
    let tenant = tenant_root(&caller, &auth)?;
    let grant = registry(&state)?
        .lock()
        .map_err(|_| ApiError::Driver("memory share registry unavailable".into()))?
        .attenuate(
            &tenant,
            parent,
            narrower,
            now(),
            &mut |claim: &FlowClaim<'_>| {
                memory_share::record(&state.state_dir, &state.authority, claim)
            },
        )?;
    Ok(Json(Minted { grant }))
}

async fn revoke(
    State(state): State<NodeState>,
    Extension(caller): Extension<CallerScope>,
    Extension(auth): Extension<AuthContext>,
    Path(share): Path<String>,
) -> Result<Json<Revoked>, ApiError> {
    let tenant = tenant_root(&caller, &auth)?;
    let epoch = registry(&state)?
        .lock()
        .map_err(|_| ApiError::Driver("memory share registry unavailable".into()))?
        .revoke(&tenant, &share, now(), &mut |claim: &FlowClaim<'_>| {
            memory_share::record(&state.state_dir, &state.authority, claim)
        })?;
    Ok(Json(Revoked { share, epoch }))
}

async fn list(
    State(state): State<NodeState>,
    Extension(caller): Extension<CallerScope>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tenant = tenant_root(&caller, &auth)?;
    let shares = registry(&state)?
        .lock()
        .map_err(|_| ApiError::Driver("memory share registry unavailable".into()))?;
    let grants = shares.grants_of(&tenant);
    serde_json::to_value(&grants)
        .map(Json)
        .map_err(|e| ApiError::Driver(format!("cannot encode grants: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn auth(id: &str) -> AuthContext {
        AuthContext::from_spiffe(id.into())
    }

    #[test]
    fn only_a_tenant_root_acts_and_only_for_itself() {
        let root = "spiffe://test.local/ns/system/sa/tenant-a";
        assert_eq!(
            tenant_root(&CallerScope::NodeWide, &auth(root)).unwrap(),
            TenantKey::of(root)
        );
        let federated = "spiffe://tenant-b.example/agent";
        assert_eq!(
            tenant_root(
                &CallerScope::Tenant("tenant-b.example".into()),
                &auth(federated)
            )
            .unwrap(),
            TenantKey::of(federated)
        );
        assert!(tenant_root(&CallerScope::Pod(Uuid::new_v4()), &auth(root)).is_err());
        assert!(tenant_root(&CallerScope::CiPrincipal(root.into()), &auth(root)).is_err());
    }

    #[test]
    fn a_mint_request_names_no_tenant_and_no_default_expiry() {
        let ok = r#"{"share":"team","namespace":"notes","readers":[],"writers":[{"kind":"tenant_root"}],"expiry":{"kind":"until_revoked"}}"#;
        assert!(serde_json::from_str::<MintRequest>(ok).is_ok());
        let with_tenant = r#"{"share":"team","namespace":"notes","readers":[],"writers":[],"expiry":{"kind":"until_revoked"},"tenant":"x"}"#;
        assert!(serde_json::from_str::<MintRequest>(with_tenant).is_err());
        let no_expiry = r#"{"share":"team","namespace":"notes","readers":[],"writers":[]}"#;
        assert!(serde_json::from_str::<MintRequest>(no_expiry).is_err());
        let lineage = format!(
            r#"{{"share":"team","namespace":"notes","readers":[{{"kind":"lineage","root":"{}"}}],"writers":[],"expiry":{{"kind":"at","unix":5}}}}"#,
            Uuid::new_v4()
        );
        assert!(serde_json::from_str::<MintRequest>(&lineage).is_ok());
    }

    #[test]
    fn every_route_is_the_memory_share_operation_and_no_pod_holds_it() {
        use axum::http::Method;
        let grant = Uuid::new_v4();
        for (method, path) in [
            (Method::POST, "/v1/memory/grants".to_owned()),
            (Method::GET, "/v1/memory/grants".to_owned()),
            (Method::POST, format!("/v1/memory/grants/{grant}/attenuate")),
            (Method::POST, "/v1/memory/shares/team/revoke".to_owned()),
        ] {
            assert_eq!(
                crate::auth::operation_for_route(&method, &path),
                Some(crate::auth::Operation::MemoryShare),
                "{method} {path}"
            );
        }
        let policy = crate::auth::AuthorizationPolicy::new("nucleus.local");
        let pod = auth(&format!(
            "spiffe://nucleus.local/ns/pods/sa/{}",
            Uuid::new_v4()
        ));
        let ci = auth("spiffe://nucleus.local/ns/github/sa/repo");
        let orchestrator = auth("spiffe://nucleus.local/ns/default/sa/orchestrator");
        let op = crate::auth::Operation::MemoryShare;
        assert!(policy.authorize(&pod, op).is_err());
        assert!(policy.authorize(&ci, op).is_err());
        assert!(policy.authorize(&orchestrator, op).is_ok());
    }

    /// Over the real handlers: the tenant root mints, narrows, lists and revokes, each step
    /// receipted in the node's log; a widening narrowing and a pod caller are refused.
    #[cfg(feature = "local-driver")]
    #[tokio::test]
    async fn the_tenant_root_mints_narrows_lists_and_revokes_over_http() {
        use axum::body::Body;
        use axum::http::{Method, Request, StatusCode};
        use std::os::unix::fs::PermissionsExt;
        use tower::ServiceExt;

        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::pod_api::handler_tests::state(&dir);
        let memory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(memory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        state.memory = std::sync::Arc::new(
            crate::memory_provisioning::MemoryArgs::rooted(memory.path().to_owned())
                .load(&state.host_roots, &state.state_dir, &state.authority)
                .unwrap(),
        );
        let app = routes().with_state(state.clone());
        let root = "spiffe://nucleus.local/ns/default/sa/orchestrator";
        let call = |method: Method, path: String, caller: CallerScope, body: String| {
            let app = app.clone();
            async move {
                let response = app
                    .oneshot(
                        Request::builder()
                            .method(method)
                            .uri(path)
                            .header("content-type", "application/json")
                            .extension(AuthContext::from_spiffe(root.into()))
                            .extension(caller)
                            .body(Body::from(body))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let status = response.status();
                let bytes = axum::body::to_bytes(response.into_body(), 65536)
                    .await
                    .unwrap();
                (
                    status,
                    serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
                )
            }
        };
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let mint = format!(
            r#"{{"share":"team","namespace":"notes","readers":[{{"kind":"lineage","root":"{b}"}}],"writers":[{{"kind":"lineage","root":"{a}"}}],"expiry":{{"kind":"until_revoked"}}}}"#
        );
        let (status, _) = call(
            Method::POST,
            "/v1/memory/grants".into(),
            CallerScope::Pod(a),
            mint.clone(),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a pod is no tenant root");
        let (status, minted) = call(
            Method::POST,
            "/v1/memory/grants".into(),
            CallerScope::NodeWide,
            mint,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{minted}");
        let grant = minted["grant"].as_str().unwrap().to_owned();
        let widen = format!(
            r#"{{"readers":[],"writers":[{{"kind":"lineage","root":"{b}"}}],"expiry":{{"kind":"until_revoked"}}}}"#
        );
        let (status, refused) = call(
            Method::POST,
            format!("/v1/memory/grants/{grant}/attenuate"),
            CallerScope::NodeWide,
            widen,
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(
            refused["error"].as_str().unwrap().contains("as a writer"),
            "{refused}"
        );
        let narrow = format!(
            r#"{{"readers":[{{"kind":"lineage","root":"{a}"}}],"writers":[],"expiry":{{"kind":"until_revoked"}}}}"#
        );
        let (status, child) = call(
            Method::POST,
            format!("/v1/memory/grants/{grant}/attenuate"),
            CallerScope::NodeWide,
            narrow,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{child}");
        let (status, listed) = call(
            Method::GET,
            "/v1/memory/grants".into(),
            CallerScope::NodeWide,
            String::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(listed.as_array().unwrap().len(), 2);
        let (status, revoked) = call(
            Method::POST,
            "/v1/memory/shares/team/revoke".into(),
            CallerScope::NodeWide,
            String::new(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(revoked["epoch"], 1);
        let log = std::fs::read_to_string(memory_share::flow_log_path(&state.state_dir)).unwrap();
        for event in [
            "memory_share_mint",
            "memory_share_attenuate",
            "memory_share_revoke",
        ] {
            assert!(log.contains(event), "{event} is receipted");
        }
    }
}
