//! Raw output remains a supervisor observation, independent of console rendering
//! and guest-writable files. Check lineage and the completed claim before reads.
use super::{ApiError, NodeState, observe_claim, supervisor_error};
use axum::extract::{Extension, Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use nucleus_ci_verdict::execution::ExecutionClaim;
use nucleus_spec::workload_result::MAX_LOG_BYTES;
use sha2::{Digest, Sha256};
use uuid::Uuid;

enum Stream {
    Stdout,
    Stderr,
}
impl Stream {
    fn name(&self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
    fn digest<'a>(&self, claim: &'a ExecutionClaim) -> &'a str {
        match self {
            Self::Stdout => &claim.stdout_sha256,
            Self::Stderr => &claim.stderr_sha256,
        }
    }
}

pub(super) async fn stdout(
    State(state): State<NodeState>,
    Extension(caller): Extension<crate::pod_api::Caller>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    serve(state, caller, id, Stream::Stdout).await
}
pub(super) async fn stderr(
    State(state): State<NodeState>,
    Extension(caller): Extension<crate::pod_api::Caller>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    serve(state, caller, id, Stream::Stderr).await
}

async fn serve(
    state: NodeState,
    caller: crate::pod_api::Caller,
    id: Uuid,
    stream: Stream,
) -> Result<Response, ApiError> {
    let (claim, address) = observe_claim(&state, caller, id).await?;
    let bytes = fetch(&state.http_client, &address, &stream, stream.digest(&claim)).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CACHE_CONTROL, "private, no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        bytes,
    )
        .into_response())
}

async fn fetch(
    client: &reqwest::Client,
    address: &str,
    stream: &Stream,
    digest: &str,
) -> Result<Vec<u8>, ApiError> {
    let mut response = client
        .get(format!(
            "{}/v1/workload/logs/{}",
            address.trim_end_matches('/'),
            stream.name()
        ))
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| supervisor_error("reading raw workload log", e))?;
    if response
        .content_length()
        .is_some_and(|size| size > MAX_LOG_BYTES as u64)
    {
        return Err(ApiError::Driver(
            "raw workload log exceeds capture limit".into(),
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| supervisor_error("reading raw workload log body", e))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_LOG_BYTES {
            return Err(ApiError::Driver(
                "raw workload log exceeds capture limit".into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    if hex::encode(Sha256::digest(&bytes)) != digest {
        return Err(ApiError::Driver(
            "raw workload log differs from supervisor observation".into(),
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router,
        body::{Body, Bytes},
        http::StatusCode,
        routing::get,
    };

    async fn read(body: Body, status: StatusCode, digest: &str) -> Result<Vec<u8>, ApiError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let body = std::sync::Arc::new(tokio::sync::Mutex::new(Some(body)));
        let app = Router::new().route(
            "/v1/workload/logs/stdout",
            get(move || async move { (status, body.lock().await.take().unwrap()) }),
        );
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        let result = fetch(
            &reqwest::Client::new(),
            &format!("http://{address}"),
            &Stream::Stdout,
            digest,
        )
        .await;
        task.abort();
        result
    }

    #[tokio::test]
    async fn raw_log_bytes_must_match_the_completed_observation() {
        let bytes = b"raw\0\xff\nlast";
        let digest = hex::encode(Sha256::digest(bytes));
        assert_eq!(
            read(Body::from(bytes.as_slice()), StatusCode::OK, &digest)
                .await
                .unwrap(),
            bytes
        );
        assert!(
            read(Body::from("changed"), StatusCode::OK, &digest)
                .await
                .unwrap_err()
                .to_string()
                .contains("differs from supervisor")
        );
        assert!(
            read(Body::empty(), StatusCode::PAYLOAD_TOO_LARGE, &digest)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn chunked_logs_cannot_bypass_the_capture_bound() {
        let chunks = tokio_stream::iter([
            Ok::<_, std::io::Error>(Bytes::from(vec![b'x'; MAX_LOG_BYTES / 2])),
            Ok(Bytes::from(vec![b'x'; MAX_LOG_BYTES / 2 + 1])),
        ]);
        let error = read(Body::from_stream(chunks), StatusCode::OK, &"a".repeat(64))
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("exceeds capture limit"),
            "{error}"
        );
    }
}
