//! `GET /v1/pods/{id}/ended`: whether a pod this node created has ended.
//!
//! A caller that created a pod and then lost track of it (its response was
//! lost, or the caller only reconciles later) settles its own record from the
//! node's listing. Within one node life that works: an exited pod stays in the
//! registry, listed with its exit state. A node restart empties the registry,
//! and from then on the listing cannot tell a pod that ended in an earlier life
//! from one that never existed. This route answers that one question by id.
//!
//! * A pod in this life's registry that has exited or errored: `200`, `ended`
//!   is `exited` or `error`, with the pod as the listing shows it. Scoped like
//!   every other per-pod read: a pod the caller may not manage is `404`.
//! * A pod in this life's registry that is still running: `409`.
//! * A pod whose state directory the node found when it restored from disk at
//!   startup, and that this life has not registered: `200`, `ended` is
//!   `previous_node_life`. No pod of a previous life runs in this one
//!   (`pod_authority::previous_life`). The directory is created when the node
//!   accepts a create, before the spawn, so this says the node took the create,
//!   not that the workload started; a caller that holds the node's create
//!   response for this id knows that part. Answered only to a node-wide caller:
//!   the node keeps no lineage for a previous life's pod that a pod could not
//!   have written, so no narrower scope can be checked.
//! * Anything else: `404`.

use axum::Json;
use axum::extract::{Extension, Path, State};
use serde::Serialize;
use uuid::Uuid;

use crate::auth::CallerScope;
use crate::{ApiError, NodeState, PodInfo, PodState};

/// Why a pod is no longer running.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Cause {
    /// Registered in this life, now `Exited`.
    Exited,
    /// Registered in this life, now `Error`.
    Error,
    /// Created by an earlier life of this node; nothing of it runs now.
    PreviousNodeLife,
}

#[derive(Debug, Serialize)]
pub(crate) struct Ended {
    pub(crate) id: Uuid,
    pub(crate) ended: Cause,
    /// The pod as `GET /v1/pods` shows it, for a pod of this life.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) pod: Option<PodInfo>,
}

pub(crate) async fn ended(
    State(state): State<NodeState>,
    Extension(caller): Extension<CallerScope>,
    Path(id): Path<Uuid>,
) -> Result<Json<Ended>, ApiError> {
    let registered = state.pods.lock().await.contains_key(&id);
    if registered {
        let pod = super::get_pod_for_caller(&state, id, &caller).await?;
        let info = pod.info().await;
        let ended = match info.state {
            PodState::Running => return Err(ApiError::Conflict("pod is running".into())),
            PodState::Exited { .. } => Cause::Exited,
            PodState::Error { .. } => Cause::Error,
        };
        return Ok(Json(Ended {
            id,
            ended,
            pod: Some(info),
        }));
    }
    if matches!(caller, CallerScope::NodeWide) && state.authority.of_previous_life(id).await {
        return Ok(Json(Ended {
            id,
            ended: Cause::PreviousNodeLife,
            pod: None,
        }));
    }
    Err(ApiError::NotFound)
}

// The handler fixtures (`pod_api::handler_tests`) need the local driver.
#[cfg(all(test, feature = "local-driver"))]
mod tests {
    use super::*;
    use crate::pod_api::handler_tests::{register, state};
    use axum::response::IntoResponse;

    async fn ask(st: &NodeState, caller: CallerScope, id: Uuid) -> (u16, serde_json::Value) {
        let response = ended(State(st.clone()), Extension(caller), Path(id))
            .await
            .into_response();
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    /// The defect: after a restart the listing is empty, so a caller holding the
    /// node's create response for a pod that ran in the earlier life could not
    /// tell it from a pod that never existed. The node now says it ended.
    #[tokio::test]
    async fn a_previous_lifes_pod_reads_as_ended_to_a_node_wide_caller_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let st = state(&dir);
        let before = Uuid::new_v4();
        std::fs::create_dir_all(crate::lifecycle::pod_dir(&st.state_dir, before)).expect("pod dir");
        st.authority.restore_from_disk().await;

        let (status, body) = ask(&st, CallerScope::NodeWide, before).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["id"], before.to_string());
        assert_eq!(body["ended"], "previous_node_life");
        assert!(
            body.get("pod").is_none(),
            "no lineage is claimed for it: {body}"
        );

        // No narrower scope can be checked for it, so none is answered.
        for caller in [
            CallerScope::Pod(before),
            CallerScope::Pod(Uuid::new_v4()),
            CallerScope::CiPrincipal("spiffe://t/ns/ci/sa/x".into()),
            CallerScope::Tenant("t".into()),
        ] {
            assert_eq!(ask(&st, caller, before).await.0, 404);
        }
        // An id with no directory is unknown, not ended.
        assert_eq!(ask(&st, CallerScope::NodeWide, Uuid::new_v4()).await.0, 404);
    }

    /// A directory created in THIS life (a create in flight) is not a previous
    /// life's pod: the set is the one the node read before serving.
    #[tokio::test]
    async fn a_directory_created_after_restore_is_not_ended() {
        let dir = tempfile::tempdir().expect("tempdir");
        let st = state(&dir);
        st.authority.restore_from_disk().await;
        let later = Uuid::new_v4();
        std::fs::create_dir_all(crate::lifecycle::pod_dir(&st.state_dir, later)).expect("pod dir");
        assert_eq!(ask(&st, CallerScope::NodeWide, later).await.0, 404);
    }

    /// In this life: running is 409, an exited pod is ended with its listing row.
    #[tokio::test]
    async fn a_pod_of_this_life_is_ended_once_it_exits() {
        let dir = tempfile::tempdir().expect("tempdir");
        let st = state(&dir);
        let id = register(&st, None).await;
        let (status, body) = ask(&st, CallerScope::NodeWide, id).await;
        assert_eq!(status, 409, "{body}");

        let _cancelled = crate::pod_api::cancel_pod(
            State(st.clone()),
            Extension(CallerScope::NodeWide),
            Path(id),
        )
        .await
        .expect("cancels");
        let (status, body) = ask(&st, CallerScope::NodeWide, id).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["ended"], "exited");
        assert_eq!(body["pod"]["id"], id.to_string());
        assert!(body["pod"]["parent_pod_id"].is_null());
        // Scoped like every per-pod read.
        assert_eq!(ask(&st, CallerScope::Pod(Uuid::new_v4()), id).await.0, 404);
    }
}
