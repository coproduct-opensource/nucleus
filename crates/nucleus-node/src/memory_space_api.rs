//! The memory-space API: declare spaces, record and revoke binding policies, revoke a space,
//! and publish a binding's branch (`memory_space`, `memory_binding`).
//!
//! # Who may call it
//!
//! The tenant a request acts for is never named in the request. For the tenant's root identity
//! it is the hash of the caller's own verified SPIFFE ID, the same root identity a pod it
//! creates is issued under (`AdmittedPodPlan::owner`); for a pod it is the root identity the
//! node recorded for that pod. So no caller acts for another tenant.
//!
//! * Declaring a space, revoking a policy or a space, and listing: the tenant root only
//!   (`Operation::MemorySpaces`, refused to pods and CI identities at the route).
//! * Recording a policy (`Operation::MemoryBinding`): the tenant root, or any caller of the
//!   tenant that cites a standing owner decision covering `memory.bind:<space>` (and
//!   `memory.publish:<space>` for a policy that may publish). The policy expires no later than
//!   the decision, and every bind and publish under it re-cites the decision.
//! * Publishing (`Operation::MemoryBinding`): the binding's tenant root, or the pod holding it.
use std::collections::{BTreeMap, BTreeSet};

use axum::extract::{Extension, Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use nucleus_provenance_memory::Pin;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::{AuthContext, CallerScope};
use crate::memory_binding::Publisher;
use crate::memory_flow::{self, FlowClaim};
use crate::memory_space::{
    self, Audience, DecisionCiter, Expiry, Mode, PolicyAuthority, PolicyRequest, Registry,
    SchemaAtom, SpaceId, SpaceName, SpaceRequest, TenantKey, ViewSpec,
};
use crate::{ApiError, NodeState};

pub(crate) fn routes() -> Router<NodeState> {
    Router::new()
        .route("/v1/memory/spaces", get(list).post(create_space))
        .route("/v1/memory/spaces/{space}/revoke", post(revoke_space))
        .route("/v1/memory/spaces/{space}/policies", post(create_policy))
        .route(
            "/v1/memory/spaces/{space}/policies/{policy}/revoke",
            post(revoke_policy),
        )
        .route("/v1/memory/bindings/{binding}/publish", post(publish))
}

/// Who is asking, and for which tenant.
#[derive(Debug, PartialEq, Eq)]
enum Caller {
    TenantRoot(TenantKey),
    Pod { pod: Uuid, tenant: TenantKey },
}

impl Caller {
    fn tenant(&self) -> &TenantKey {
        match self {
            Caller::TenantRoot(tenant) | Caller::Pod { tenant, .. } => tenant,
        }
    }
}

/// The tenant a caller is the root of, or a refusal for a caller that is no tenant's root.
fn tenant_root(caller: &CallerScope, auth: &AuthContext) -> Result<TenantKey, ApiError> {
    match caller {
        CallerScope::NodeWide | CallerScope::Tenant(_) => Ok(TenantKey::of(&auth.spiffe_id)),
        CallerScope::Pod(_) | CallerScope::CiPrincipal(_) => Err(ApiError::Authority(
            "only a tenant's root identity declares or revokes memory spaces and policies".into(),
        )),
    }
}

/// The caller, with the tenant the node recorded for a pod.
async fn caller(
    state: &NodeState,
    scope: &CallerScope,
    auth: &AuthContext,
) -> Result<Caller, ApiError> {
    match scope {
        CallerScope::Pod(pod) => {
            let owner = state
                .pods
                .lock()
                .await
                .get(pod)
                .and_then(|handle| handle.owner.clone())
                .ok_or_else(|| {
                    ApiError::Authority("the calling pod has no recorded tenant".into())
                })?;
            Ok(Caller::Pod {
                pod: *pod,
                tenant: TenantKey::of(&owner),
            })
        }
        CallerScope::NodeWide | CallerScope::Tenant(_) | CallerScope::CiPrincipal(_) => {
            tenant_root(scope, auth).map(Caller::TenantRoot)
        }
    }
}

fn now() -> u64 {
    crate::memory_provisioning::now_unix()
}

fn registry(state: &NodeState) -> Result<std::sync::MutexGuard<'_, Registry>, ApiError> {
    state
        .memory
        .registry()
        .ok_or_else(|| {
            ApiError::InvalidSpec("memory spaces require an operator --memory-root".into())
        })?
        .lock()
        .map_err(|_| ApiError::Driver("memory space registry unavailable".into()))
}

fn citer(state: &NodeState) -> Option<&dyn DecisionCiter> {
    state
        .decisions
        .as_deref()
        .map(|decisions| decisions as &dyn DecisionCiter)
}

fn space_ref(reference: &str) -> Result<SpaceId, ApiError> {
    SpaceId::parse(reference).map_err(ApiError::from)
}

/// A space to declare.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateSpace {
    space: String,
    schema: BTreeSet<SchemaAtom>,
    quota_bytes: u64,
}

/// Who a requested policy admits. No legacy audience: only migration records one.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum RequestedAudience {
    Lineage { root: Uuid },
    Workspace { selector: BTreeMap<String, String> },
    TenantAll,
}

/// What a requested policy rests on.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum RequestedAuthority {
    TenantRoot,
    Decision { id: String },
}

/// A policy to record. Every field is required: no default mode, view, audience or expiry.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreatePolicy {
    audience: RequestedAudience,
    mode: Mode,
    view: ViewSpec,
    may_publish: bool,
    allocation_bytes: u64,
    expiry: Expiry,
    authority: RequestedAuthority,
}

/// A publish: the head the caller expects (compare-and-swap).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublishRequest {
    expected: Pin,
}

#[derive(Debug, Serialize)]
struct Created {
    space: String,
}

#[derive(Debug, Serialize)]
struct PolicyCreated {
    policy: Uuid,
}

#[derive(Debug, Serialize)]
struct Revoked {
    space: String,
    epoch: u32,
}

#[derive(Debug, Serialize)]
struct Published {
    head: Pin,
}

async fn create_space(
    State(state): State<NodeState>,
    Extension(scope): Extension<CallerScope>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<CreateSpace>,
) -> Result<Json<Created>, ApiError> {
    let tenant = tenant_root(&scope, &auth)?;
    let request = SpaceRequest {
        name: SpaceName::new(&request.space)?,
        schema: request.schema,
        quota_bytes: request.quota_bytes,
    };
    let id =
        registry(&state)?.create_space(&tenant, request, now(), &mut |claim: &FlowClaim<'_>| {
            memory_flow::record(&state.state_dir, &state.authority, claim)
        })?;
    Ok(Json(Created {
        space: id.reference(),
    }))
}

/// Decide what a requested policy rests on, for this caller: the tenant root's own word, or a
/// standing decision that covers the policy's capabilities now. Returns the authority to record
/// and the expiry, clamped to the decision's window.
fn decide_authority(
    state: &NodeState,
    caller: &Caller,
    space: &SpaceId,
    requested: RequestedAuthority,
    may_publish: bool,
    expiry: Expiry,
) -> Result<(PolicyAuthority, Expiry), ApiError> {
    match requested {
        RequestedAuthority::TenantRoot => match caller {
            Caller::TenantRoot(_) => Ok((PolicyAuthority::TenantRoot, expiry)),
            Caller::Pod { .. } => Err(ApiError::Authority(
                "a pod records a memory policy only by citing an owner decision".into(),
            )),
        },
        RequestedAuthority::Decision { id } => {
            let citer = citer(state).ok_or_else(|| {
                ApiError::Authority("this node verifies no owner decisions".into())
            })?;
            let at = now();
            let cite = |capability: String| {
                citer.cite(&id, &capability, at).map_err(|why| {
                    ApiError::Authority(format!(
                        "owner decision {id} does not cover {capability}: {why}"
                    ))
                })
            };
            let mut not_after = cite(memory_space::bind_capability(space))?;
            if may_publish {
                not_after = not_after.min(cite(memory_space::publish_capability(space))?);
            }
            let ends = not_after.saturating_add(1);
            let expiry = match expiry {
                Expiry::At(requested) => Expiry::At(requested.min(ends)),
                Expiry::UntilRevoked => Expiry::At(ends),
            };
            Ok((PolicyAuthority::Decision { id }, expiry))
        }
    }
}

async fn create_policy(
    State(state): State<NodeState>,
    Extension(scope): Extension<CallerScope>,
    Extension(auth): Extension<AuthContext>,
    Path(space): Path<String>,
    Json(request): Json<CreatePolicy>,
) -> Result<Json<PolicyCreated>, ApiError> {
    let caller = caller(&state, &scope, &auth).await?;
    let space = space_ref(&space)?;
    let CreatePolicy {
        audience,
        mode,
        view,
        may_publish,
        allocation_bytes,
        expiry,
        authority,
    } = request;
    let (authority, expiry) =
        decide_authority(&state, &caller, &space, authority, may_publish, expiry)?;
    let audience = match audience {
        RequestedAudience::Lineage { root } => Audience::Lineage { root },
        RequestedAudience::Workspace { selector } => Audience::Workspace { selector },
        RequestedAudience::TenantAll => Audience::TenantAll,
    };
    let policy = registry(&state)?.create_policy(
        caller.tenant(),
        &space,
        PolicyRequest {
            audience,
            mode,
            view,
            may_publish,
            allocation_bytes,
            expiry,
            authority,
        },
        now(),
        &mut |claim: &FlowClaim<'_>| memory_flow::record(&state.state_dir, &state.authority, claim),
    )?;
    Ok(Json(PolicyCreated { policy }))
}

async fn revoke_policy(
    State(state): State<NodeState>,
    Extension(scope): Extension<CallerScope>,
    Extension(auth): Extension<AuthContext>,
    Path((space, policy)): Path<(String, Uuid)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tenant = tenant_root(&scope, &auth)?;
    let space = space_ref(&space)?;
    registry(&state)?.revoke_policy(&tenant, &space, policy, now(), &mut |claim: &FlowClaim<
        '_,
    >| {
        memory_flow::record(&state.state_dir, &state.authority, claim)
    })?;
    Ok(Json(
        serde_json::json!({ "policy": policy, "revoked": true }),
    ))
}

async fn revoke_space(
    State(state): State<NodeState>,
    Extension(scope): Extension<CallerScope>,
    Extension(auth): Extension<AuthContext>,
    Path(space): Path<String>,
) -> Result<Json<Revoked>, ApiError> {
    let tenant = tenant_root(&scope, &auth)?;
    let id = space_ref(&space)?;
    let epoch =
        registry(&state)?.revoke_space(&tenant, &id, now(), &mut |claim: &FlowClaim<'_>| {
            memory_flow::record(&state.state_dir, &state.authority, claim)
        })?;
    Ok(Json(Revoked {
        space: id.reference(),
        epoch,
    }))
}

async fn list(
    State(state): State<NodeState>,
    Extension(scope): Extension<CallerScope>,
    Extension(auth): Extension<AuthContext>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tenant = tenant_root(&scope, &auth)?;
    Ok(Json(registry(&state)?.spaces_of(&tenant)))
}

async fn publish(
    State(state): State<NodeState>,
    Extension(scope): Extension<CallerScope>,
    Extension(auth): Extension<AuthContext>,
    Path(binding): Path<Uuid>,
    Json(request): Json<PublishRequest>,
) -> Result<Json<Published>, ApiError> {
    let caller = caller(&state, &scope, &auth).await?;
    let publisher = match &caller {
        Caller::TenantRoot(tenant) => Publisher::TenantRoot(tenant),
        Caller::Pod { pod, .. } => Publisher::Pod(*pod),
    };
    let at = now();
    let mut registry = registry(&state)?;
    let admitted = registry.admit_publish(binding, publisher, at, citer(&state))?;
    let head = registry.publish(admitted, request.expected, at, &mut |claim: &FlowClaim<
        '_,
    >| {
        memory_flow::record(&state.state_dir, &state.authority, claim)
    })?;
    Ok(Json(Published { head }))
}

#[cfg(test)]
#[path = "memory_space_api_tests.rs"]
mod tests;
