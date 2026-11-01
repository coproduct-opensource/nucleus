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
//!
//! ## `spent_micro_usd`: what the pod was charged
//!
//! On a `200`, `spent_micro_usd` is what the node's budget ledger was charged for
//! the pod when it was released, in micro-USD (1 USD = 1_000_000), rounded up: its
//! metered spend, at most its allocation, when its federated binding settles
//! `metered`, else its whole allocation (`pod_authority::settle`). The release
//! keeps it beside the pod (`pods/<id>/settled-spend.json`), so it is reported
//! for a pod of a previous life too, settled in that life or at this one's
//! startup (`pod_authority::previous_life`).
//!
//! **Absent means unknown, never 0.** It is absent when the pod has not been
//! released yet (a pod reads `exited` as soon as it stops; the reaper releases it
//! after cleanup, so a caller may ask again), when no ledger above the pod was
//! charged (admitted by the root minter, or not through the authority at all),
//! when the ledger held no allocation for it, when the record could not be
//! written or read, and for a pod released before the record existed. A caller
//! settling a reservation from this route must treat absent as the whole
//! reservation spent: fail-closed. A `0` is reported only when a ledger was
//! charged nothing (a metered pod that metered nothing, or an unspawned launch).

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
    /// What the node's budget ledger was charged for the pod at its release, in
    /// micro-USD. Absent is unknown, never 0: see the module docs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) spent_micro_usd: Option<u64>,
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
            spent_micro_usd: state.authority.settled_spend(id).await,
        }));
    }
    if matches!(caller, CallerScope::NodeWide) && state.authority.of_previous_life(id).await {
        return Ok(Json(Ended {
            id,
            ended: Cause::PreviousNodeLife,
            pod: None,
            spent_micro_usd: state.authority.settled_spend(id).await,
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

// What the node's budget ledger was charged for an ended pod (`spent_micro_usd`).
#[cfg(all(test, feature = "local-driver"))]
mod spend_tests {
    use super::*;
    use crate::pod_api::handler_tests::{register, state};
    use crate::pod_authority::Admission;
    use axum::response::IntoResponse;

    async fn ask(st: &NodeState, id: Uuid) -> (u16, serde_json::Value) {
        let response = ended(
            State(st.clone()),
            Extension(CallerScope::NodeWide),
            Path(id),
        )
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

    fn spec(budget_usd: u32) -> nucleus_spec::PodSpec {
        let mut lattice = portcullis::PermissionLattice::permissive();
        lattice.budget.max_cost_usd = rust_decimal::Decimal::from(budget_usd);
        let mut spec: nucleus_spec::PodSpec = serde_json::from_str(
            r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"policy":{"type":"profile","name":"default"}}}"#,
        )
        .expect("minimal spec");
        spec.spec.work_dir = std::path::PathBuf::from("/work");
        spec.spec.policy = nucleus_spec::PolicySpec::Inline {
            lattice: Box::new(lattice),
        };
        spec
    }

    /// A pod admitted by the root minter: it holds an allocation, but no ledger
    /// above it is charged when it ends.
    async fn admit_root(st: &NodeState, id: Uuid, budget_usd: u32) {
        let by = Admission {
            caller_spiffe_id: st.authority.root_minter().to_string(),
            caller_pod: None,
            header_cert: None,
        };
        st.authority
            .admit_kept(&by, &spec(budget_usd), id)
            .await
            .expect("root admits");
    }

    /// A child of `parent`, charged to `parent`'s ledger.
    async fn admit_child(st: &NodeState, parent: Uuid, id: Uuid, budget_usd: u32) {
        let by = Admission {
            caller_spiffe_id: st.authority.pod_spiffe_id(parent),
            caller_pod: Some(parent),
            header_cert: None,
        };
        st.authority
            .admit_kept(&by, &spec(budget_usd), id)
            .await
            .expect("parent admits its child");
    }

    async fn cancel(st: &NodeState, id: Uuid) {
        let _cancelled = crate::pod_api::cancel_pod(
            State(st.clone()),
            Extension(CallerScope::NodeWide),
            Path(id),
        )
        .await
        .expect("cancels");
    }

    /// An exited pod charged to its parent's ledger reports what that ledger
    /// was charged at release; before the release settles it, nothing is
    /// claimed.
    #[tokio::test]
    async fn an_exited_pod_reports_what_its_ledger_was_charged() {
        let dir = tempfile::tempdir().expect("tempdir");
        let st = state(&dir);
        let parent = Uuid::new_v4();
        admit_root(&st, parent, 5).await;
        let child = register(&st, Some(parent)).await;
        admit_child(&st, parent, child, 2).await;

        cancel(&st, child).await;
        let (status, body) = ask(&st, child).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["ended"], "exited");
        assert!(
            body.get("spent_micro_usd").is_none(),
            "exited but not yet settled: unknown, never 0: {body}"
        );

        // What the reaper does once the pod is cleaned up.
        st.authority.release_child(child).await;
        let (status, body) = ask(&st, child).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            body["spent_micro_usd"], 2_000_000,
            "an unmetered binding's pod is charged its whole $2 allocation: {body}"
        );
    }

    /// A pod with no ledger above it (admitted by the root minter, or never
    /// admitted through the authority at all) omits the field.
    #[tokio::test]
    async fn a_pod_no_ledger_was_charged_for_omits_its_spend() {
        let dir = tempfile::tempdir().expect("tempdir");
        let st = state(&dir);
        let rooted = register(&st, None).await;
        admit_root(&st, rooted, 5).await;
        let bare = register(&st, None).await;
        for id in [rooted, bare] {
            cancel(&st, id).await;
            st.authority.release_child(id).await;
            let (status, body) = ask(&st, id).await;
            assert_eq!(status, 200, "{body}");
            assert!(body.get("spent_micro_usd").is_none(), "{body}");
        }
    }

    /// After a restart: a pod settled in the earlier life, and one the earlier
    /// life left registered (settled at this startup), both report their charge.
    /// The root-admitted parent, and a record naming another pod, report none.
    #[tokio::test]
    async fn a_previous_lifes_pod_reports_its_persisted_charge() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = state(&dir);
        let parent = Uuid::new_v4();
        admit_root(&first, parent, 5).await;
        let settled = Uuid::new_v4();
        admit_child(&first, parent, settled, 2).await;
        first.authority.release_child(settled).await;
        let stranded = Uuid::new_v4();
        admit_child(&first, parent, stranded, 1).await;
        // Killed here: `stranded` and `parent` are never released by this life.

        // A record copied from another pod's directory says nothing of this one.
        let foreign = Uuid::new_v4();
        let foreign_dir = crate::lifecycle::pod_dir(&first.state_dir, foreign);
        std::fs::create_dir_all(&foreign_dir).expect("pod dir");
        std::fs::copy(
            crate::lifecycle::pod_dir(&first.state_dir, settled).join("settled-spend.json"),
            foreign_dir.join("settled-spend.json"),
        )
        .expect("a settled record was written for the released pod");
        drop(first);

        let next = state(&dir);
        next.authority.restore_from_disk().await;
        next.authority.release_previous_life().await;

        for (id, spent) in [(settled, Some(2_000_000)), (stranded, Some(1_000_000))] {
            let (status, body) = ask(&next, id).await;
            assert_eq!(status, 200, "{body}");
            assert_eq!(body["ended"], "previous_node_life");
            assert_eq!(
                body.get("spent_micro_usd").and_then(|v| v.as_u64()),
                spent,
                "{body}"
            );
        }
        for id in [parent, foreign] {
            let (status, body) = ask(&next, id).await;
            assert_eq!(status, 200, "{body}");
            assert!(body.get("spent_micro_usd").is_none(), "{body}");
        }
    }
}
