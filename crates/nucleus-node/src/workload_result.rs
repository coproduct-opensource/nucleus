//! Fetch the supervising proxy's read-only observation through the node-owned
//! proxy bridge. Pod lineage is checked before revealing or contacting it.
//! This response does not itself assert a sandbox tier or carry a signature.

use axum::Json;
use axum::extract::{Extension, Path, State};
use nucleus_spec::workload_result::WorkloadResult;
use uuid::Uuid;

use crate::{ApiError, NodeState, pod_api};

pub(crate) async fn get(
    State(state): State<NodeState>,
    Extension(caller): Extension<Option<Uuid>>,
    Path(id): Path<Uuid>,
) -> Result<Json<WorkloadResult>, ApiError> {
    let pod = pod_api::get_pod_for_caller(&state, id, caller).await?;
    let address =
        pod.proxy_addr.lock().await.clone().ok_or_else(|| {
            ApiError::Driver("workload supervisor is not reachable yet".to_string())
        })?;
    fetch(&state.http_client, &address).await.map(Json)
}

async fn fetch(client: &reqwest::Client, address: &str) -> Result<WorkloadResult, ApiError> {
    let mut response = client
        .get(format!(
            "{}/v1/workload/result",
            address.trim_end_matches('/')
        ))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| ApiError::Driver(format!("reading workload supervisor: {e}")))?;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| ApiError::Driver(format!("reading workload result body: {e}")))?
    {
        if body.len().saturating_add(chunk.len()) > 16 * 1024 {
            return Err(ApiError::Driver("workload result exceeds 16 KiB".into()));
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|e| ApiError::Driver(format!("malformed workload supervisor result: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;

    #[tokio::test]
    async fn an_unavailable_supervisor_is_an_error_not_a_pass() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = axum::Router::new().route(
            "/v1/workload/result",
            get(|| async { axum::http::StatusCode::SERVICE_UNAVAILABLE }),
        );
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        let result = fetch(&reqwest::Client::new(), &format!("http://{address}")).await;
        task.abort();
        assert!(result.is_err());
    }
}
