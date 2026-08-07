//! The pod-management HTTP surface: list, logs, cancel.
//!
//! Extracted from `main.rs` because the line ratchet on that file requires
//! anything added to be paid for by something taken out, and these four
//! functions are the most cohesive block available: they are the entire
//! read/cancel API over `NodeState.pods`, and they are what the ownership work
//! extends next. Extracting them here means that change edits a 60-line module
//! rather than growing a 4000-line one further.
//!
//! Nothing about the behaviour changes in this move.

use crate::{ApiError, NodeState, PodHandle, PodInfo};
use axum::extract::{Path as AxumPath, State};
use axum::Json;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) async fn list_pods(
    State(state): State<NodeState>,
) -> Result<Json<Vec<PodInfo>>, ApiError> {
    let infos = collect_pod_infos(&state).await;
    Ok(Json(infos))
}

pub(crate) async fn collect_pod_infos(state: &NodeState) -> Vec<PodInfo> {
    let pods: Vec<Arc<PodHandle>> = {
        let guard = state.pods.lock().await;
        guard.values().cloned().collect()
    };

    let mut infos = Vec::with_capacity(pods.len());
    for pod in pods {
        infos.push(pod.info().await);
    }

    infos
}

pub(crate) async fn pod_logs(
    State(state): State<NodeState>,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<String, ApiError> {
    let pod = get_pod(&state, id).await?;
    let logs = tokio::fs::read_to_string(&pod.log_path)
        .await
        .unwrap_or_default();
    Ok(logs)
}

pub(crate) async fn cancel_pod(
    State(state): State<NodeState>,
    AxumPath(id): AxumPath<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let pod = get_pod(&state, id).await?;
    pod.cancel().await?;
    Ok(Json(serde_json::json!({"status": "cancelled"})))
}

pub(crate) async fn get_pod(state: &NodeState, id: Uuid) -> Result<Arc<PodHandle>, ApiError> {
    let guard = state.pods.lock().await;
    guard.get(&id).cloned().ok_or(ApiError::NotFound)
}
