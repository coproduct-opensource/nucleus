//! Collect exact bounded artifact bytes through the proxy's mediated reader,
//! then sign their identities together with the observed execution. No hash or
//! success claim supplied by a workload is used as artifact evidence.

use axum::{
    Json,
    extract::{Extension, Path, State},
};
use base64::Engine as _;
use nucleus_ci_verdict::execution::ArtifactIdentity;
use nucleus_receipt::Receipt;
use nucleus_spec::workload_result::MAX_ARTIFACT_BYTES;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

use crate::{ApiError, NodeState, workload_result};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    artifacts: BTreeMap<String, String>,
}

#[derive(Serialize)]
pub(crate) struct Bundle {
    receipt: Receipt,
    /// Standard base64; hashes and sizes in the signed body cover decoded bytes.
    artifacts: BTreeMap<String, String>,
}

pub(crate) async fn collect(
    State(state): State<NodeState>,
    Extension(caller): Extension<Option<Uuid>>,
    Path(id): Path<Uuid>,
    Json(request): Json<Request>,
) -> Result<Json<Bundle>, ApiError> {
    validate_manifest(&request.artifacts)?;
    // This establishes lineage and a completed workload before any artifact read.
    let (mut claim, address) = workload_result::observe_claim(&state, caller, id).await?;
    let mut artifacts = BTreeMap::new();
    let mut remaining = MAX_ARTIFACT_BYTES;
    for (name, path) in request.artifacts {
        let bytes = fetch(&state.http_client, &address, &path, remaining).await?;
        remaining = remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| ApiError::Driver("artifact budget exhausted".into()))?;
        claim.artifacts.insert(
            name.clone(),
            ArtifactIdentity {
                path,
                sha256: hex::encode(Sha256::digest(&bytes)),
                size: bytes.len() as u64,
            },
        );
        artifacts.insert(
            name,
            base64::engine::general_purpose::STANDARD.encode(bytes),
        );
    }
    let receipt = workload_result::sign_claim(&state, id, claim)?;
    Ok(Json(Bundle { receipt, artifacts }))
}

fn validate_manifest(artifacts: &BTreeMap<String, String>) -> Result<(), ApiError> {
    if artifacts.is_empty() || artifacts.len() > 8 {
        return Err(ApiError::InvalidSpec(
            "request between one and eight artifacts".into(),
        ));
    }
    for (name, path) in artifacts {
        if name.is_empty()
            || matches!(name.as_str(), "." | "..")
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
            || path.is_empty()
            || path.len() > 4096
            || !std::path::Path::new(path).components().all(|part| {
                matches!(
                    part,
                    std::path::Component::Normal(_) | std::path::Component::CurDir
                )
            })
        {
            return Err(ApiError::InvalidSpec(
                "artifact names and relative workspace paths must be valid".into(),
            ));
        }
    }
    Ok(())
}

async fn fetch(
    client: &reqwest::Client,
    address: &str,
    path: &str,
    limit: usize,
) -> Result<Vec<u8>, ApiError> {
    let mut response = client
        .post(format!("{}/v1/artifact", address.trim_end_matches('/')))
        .json(&serde_json::json!({"path": path, "max_bytes": limit}))
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| ApiError::Driver(format!("reading artifact: {e}")))?;
    if response
        .content_length()
        .is_some_and(|size| size > limit as u64)
    {
        return Err(ApiError::Driver(
            "artifact exceeds bundle size limit".into(),
        ));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| ApiError::Driver(format!("artifact body: {e}")))?
    {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(ApiError::Driver(
                "artifact exceeds bundle size limit".into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_requires_named_relative_workspace_outputs() {
        assert!(validate_manifest(&BTreeMap::new()).is_err());
        for (name, path) in [
            ("..", "output"),
            ("binary", "../outside"),
            ("binary", "/etc/passwd"),
            ("bad/name", "output"),
        ] {
            assert!(validate_manifest(&BTreeMap::from([(name.into(), path.into())])).is_err());
        }
        assert!(
            validate_manifest(&BTreeMap::from([(
                "binary".into(),
                "target/debug/nucleus-node".into()
            )]))
            .is_ok()
        );
    }

    #[tokio::test]
    async fn chunked_artifact_cannot_bypass_the_bundle_limit() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = axum::Router::new().route(
            "/v1/artifact",
            axum::routing::post(|| async {
                axum::body::Body::from_stream(tokio_stream::iter([
                    Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"abc")),
                    Ok(axum::body::Bytes::from_static(b"def")),
                ]))
            }),
        );
        let task = tokio::spawn(async move { axum::serve(listener, app).await });
        let result = fetch(
            &reqwest::Client::new(),
            &format!("http://{address}"),
            "output",
            4,
        )
        .await;
        task.abort();
        assert!(result.is_err());
    }
}
